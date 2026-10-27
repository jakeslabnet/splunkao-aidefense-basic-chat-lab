"""One application-owned OTel provider with Splunk's native Python span processor."""

from contextvars import ContextVar
from functools import partial
import hashlib
import json
import os
import re
import threading

from opentelemetry import trace
from opentelemetry.sdk.resources import Resource
from opentelemetry.sdk.trace import Event, ReadableSpan, SpanProcessor, TracerProvider
from opentelemetry.sdk.trace.export import BatchSpanProcessor
from opentelemetry.sdk.trace.id_generator import IdGenerator
from splunk_ao.deployment import DeploymentMode, O11yConfig
from splunk_ao.exporter import build_o11y_exporter, resolve_routing
from splunk_ao.otel import SplunkAOSpanProcessor

from .config import AppConfig
from .diagnostics import diagnostic, safe_error_code

CAPTURE_CONTENT: ContextVar[bool] = ContextVar("capture_content", default=True)
CONTENT_ATTRIBUTES = {
    "gen_ai.input.messages", "gen_ai.output.messages", "gen_ai.system_instructions",
    "gen_ai.prompt", "gen_ai.completion", "gen_ai.tool.call.arguments", "gen_ai.tool.call.result",
}
INPUT_ATTRIBUTES = {
    "gen_ai.input.messages", "gen_ai.prompt", "gen_ai.prompts", "gen_ai.request.prompt",
    "splunk_ao.input.messages", "llm.input_messages", "llm.prompts", "input.value",
}
CONTENT_ATTRIBUTES.update(INPUT_ATTRIBUTES | {
    "splunk_ao.output.messages", "splunk_ao.system_instructions", "llm.output_messages",
    "llm.completions", "output.value", "gen_ai.response.content",
})
INSTRUCTION_ROLES = {"system", "developer"}
_OMIT = object()
_INDEXED_INPUT = re.compile(r"^(llm\.input_messages\.)(\d+)(\.message\..+)$")


def _instruction_field(name: str) -> bool:
    # Keep gen_ai.system: its legacy meaning is the model provider, not a prompt.
    normalized = re.sub(r"[^a-z]", "", name.lower())
    return normalized.endswith(("systeminstructions", "systemprompt", "developerinstructions", "developerprompt"))


def _without_instruction_messages(value):
    if isinstance(value, dict):
        role = value.get("role", value.get("message.role"))
        if isinstance(role, str) and role.lower() in INSTRUCTION_ROLES:
            return _OMIT
        result = {}
        for key, item in value.items():
            if _instruction_field(key):
                continue
            # Actual user/assistant text is opaque, even when it contains JSON or
            # quotes a system prompt. Remove message roles, never text fragments.
            if isinstance(role, str) and role.lower() in {"user", "assistant"} and key in {"content", "text", "parts"}:
                result[key] = item
                continue
            filtered = _without_instruction_messages(item)
            if filtered is not _OMIT:
                result[key] = filtered
        return result
    if isinstance(value, (list, tuple)):
        result = []
        for item in value:
            filtered = _without_instruction_messages(item)
            if filtered is not _OMIT:
                result.append(filtered)
        return result
    return value


def _structured_input(value):
    if isinstance(value, str):
        try:
            decoded = json.loads(value)
        except (ValueError, TypeError):
            return value
        if not isinstance(decoded, (dict, list)):
            return value
        filtered = _without_instruction_messages(decoded)
        return _OMIT if filtered is _OMIT else json.dumps(filtered, separators=(",", ":"), ensure_ascii=False)
    return _without_instruction_messages(value)


def _safe_export_attributes(attributes):
    original = dict(attributes or {})
    result = {}
    indexed = {}
    for key, value in original.items():
        if _instruction_field(key):
            continue
        match = _INDEXED_INPUT.fullmatch(key)
        if match:
            indexed.setdefault(int(match[2]), []).append((match[1], match[3], value))
            continue
        filtered = _structured_input(value) if key in INPUT_ATTRIBUTES else value
        if filtered is not _OMIT:
            result[key] = filtered
    # OpenInference's legacy flattened message fields must lose the complete
    # system/developer message, then use contiguous indices for surviving input.
    next_index = 0
    for index in sorted(indexed):
        fields = indexed[index]
        role = next((value for _, suffix, value in fields if suffix == ".message.role"), None)
        if isinstance(role, str) and role.lower() in INSTRUCTION_ROLES:
            continue
        for prefix, suffix, value in fields:
            result[f"{prefix}{next_index}{suffix}"] = value
        next_index += 1
    return result


def without_instructions(span: ReadableSpan) -> ReadableSpan:
    """Remove private instruction fields at the one boundary before Splunk export."""
    events = []
    for event in span.events:
        if event.name.lower() in {"gen_ai.system.message", "gen_ai.developer.message", "gen_ai.system_instructions"}:
            continue
        original = dict(event.attributes or {})
        role = original.get("role", original.get("message.role"))
        if event.name.startswith("gen_ai.") and isinstance(role, str) and role.lower() in INSTRUCTION_ROLES:
            continue
        attributes = _safe_export_attributes(original)
        if event.name in {"gen_ai.prompt", "gen_ai.input.messages", "gen_ai.client.inference.operation.details"}:
            for key in {"messages", "prompt", "input", "content"}.intersection(attributes):
                filtered = _structured_input(attributes[key])
                if filtered is _OMIT:
                    attributes.pop(key)
                else:
                    attributes[key] = filtered
        if original and not attributes:
            continue
        events.append(Event(event.name, attributes=attributes, timestamp=event.timestamp))
    resource = span.resource
    if resource is not None:
        resource = Resource(_safe_export_attributes(resource.attributes), schema_url=resource.schema_url)
    return ReadableSpan(
        name=span.name, context=span.context, parent=span.parent, resource=resource,
        attributes=_safe_export_attributes(span.attributes), events=tuple(events),
        links=span.links, kind=span.kind, status=span.status,
        start_time=span.start_time, end_time=span.end_time,
        instrumentation_scope=span.instrumentation_scope,
    )


class OsEntropyIdGenerator(IdGenerator):
    """Never use PRNG state copied into V2 microVM snapshots."""

    def generate_span_id(self) -> int:
        return int.from_bytes(os.urandom(8), "big") or 1

    def generate_trace_id(self) -> int:
        return int.from_bytes(os.urandom(16), "big") or 1


def without_content(span: ReadableSpan) -> ReadableSpan:
    return ReadableSpan(
        name=span.name, context=span.context, parent=span.parent, resource=span.resource,
        attributes={
            key: value for key, value in (span.attributes or {}).items()
            if key not in CONTENT_ATTRIBUTES and not _INDEXED_INPUT.fullmatch(key)
            and not key.startswith("llm.output_messages.")
        },
        # GenAI events contain full message bodies; all events are omitted when capture is disabled.
        events=(), links=span.links, kind=span.kind, status=span.status,
        start_time=span.start_time, end_time=span.end_time,
        instrumentation_scope=span.instrumentation_scope,
    )


def make_splunk_processor(secret: dict, config: AppConfig):
    # SDK-native exporter construction accepts credentials directly. This avoids
    # writing SDK config files or putting tokens into process environment variables.
    routing = resolve_routing(
        DeploymentMode.O11Y, project=config.splunk_project, agent_stream=config.splunk_agent_stream,
    )
    exporter = build_o11y_exporter(
        O11yConfig(realm=secret["realm"], o11y_token=secret["o11y_token"]), routing, timeout=3,
    )
    return SplunkAOSpanProcessor(
        _exporter=exporter,
        SpanProcessor=partial(
            BatchSpanProcessor, max_queue_size=256, max_export_batch_size=64,
            schedule_delay_millis=1000, export_timeout_millis=3000,
        ),
    )


class SafeSplunkProcessor(SpanProcessor):
    """A stable provider attachment lets request-time secret rotation replace the sink."""

    def __init__(self):
        self.target = None
        self.failed = False

    def on_start(self, span, parent_context=None):
        span.set_attribute("app.capture_content", CAPTURE_CONTENT.get())
        if self.target is not None:
            try:
                self.target.on_start(span, parent_context)
            except Exception:
                self.failed = True

    def on_end(self, span):
        if self.target is not None:
            try:
                exported = span if (span.attributes or {}).get("app.capture_content", True) else without_content(span)
                self.target.on_end(without_instructions(exported))
            except Exception:
                self.failed = True

    def force_flush(self, timeout_millis=3500):
        if self.target is None:
            return True
        try:
            return self.target.force_flush(timeout_millis)
        except Exception:
            self.failed = True
            return False

    def shutdown(self):
        if self.target is not None:
            try:
                self.target.shutdown()
            except Exception:
                self.failed = True


class Telemetry:
    def __init__(self, *, processor_factory=make_splunk_processor):
        self.provider = None
        self.router = SafeSplunkProcessor()
        self._fingerprint = None
        self._configured = False
        self._lock = threading.Lock()
        self._processor_factory = processor_factory

    def initialize(self):
        with self._lock:
            if self.provider is None:
                self.provider = TracerProvider(
                    resource=Resource({"service.name": "agentcore-chat-lab", "service.version": "1"}),
                    id_generator=OsEntropyIdGenerator(),
                )
                self.provider.add_span_processor(self.router)
                trace.set_tracer_provider(self.provider)
        return self.provider.get_tracer("agentcore-chat-lab")

    def configure(self, secret: dict | None, config: AppConfig, request_id: str) -> str:
        fingerprint = hashlib.sha256(json.dumps(
            [secret, config.splunk_project, config.splunk_agent_stream], sort_keys=True,
        ).encode()).hexdigest()
        with self._lock:
            if fingerprint == self._fingerprint:
                return "unconfigured" if not self._configured else "unconfirmed"
            old = self.router.target
            self.router.target = None
            self.router.failed = False
            self._configured = False
            if old is not None:
                try:
                    old.shutdown()
                except Exception:
                    pass
            if secret is None:
                self._fingerprint = fingerprint
                return "unconfigured"
            try:
                self.router.target = self._processor_factory(secret, config)
                self._configured = True
                self._fingerprint = fingerprint
                return "unconfirmed"
            except Exception as error:
                # Retry initialization on a later request after configuration is fixed.
                diagnostic("integration_error", request_id, integration="splunk", status="error",
                           errorCode=safe_error_code(error))
                return "error"

    def flush(self, request_id: str) -> str:
        if not self._configured:
            return "unconfigured"
        try:
            flushed = self.router.force_flush(timeout_millis=3500)
            healthy = self.router.target.export_health.healthy
            if flushed and not self.router.failed and healthy is True:
                return "accepted"
        except Exception:
            pass
        diagnostic("integration_error", request_id, integration="splunk", status="error",
                   errorCode="TelemetryExportUnconfirmed")
        return "error"
