"""Cisco Python SDK hooks. Findings and inspection outages never alter the model call."""

import asyncio
from enum import Enum
import json
import logging
import time
from uuid import uuid4

from aidefense import ChatInspectionClient, Config
from aidefense.runtime.chat_models import Message, Role
from aidefense.runtime.models import Metadata
from opentelemetry.trace import Status, StatusCode
from strands.hooks import AfterModelCallEvent, BeforeModelCallEvent, HookProvider, HookRegistry

from .diagnostics import diagnostic, safe_error_code
from .telemetry import CAPTURE_CONTENT
from .validation import ChatRequest, text_messages


MAX_INSPECTION_OUTPUT_BYTES = 16 * 1024


def _inspection_input(messages: list[Message], api_key: str) -> str:
    """Capture the final SDK dialogue without serializing request credentials."""
    # History is already bounded by the application; preserve full message text
    # and roles, apart from an accidentally echoed configured inspection key.
    return json.dumps([{
        "role": message.role.value,
        "parts": [{"type": "text", "content": message.content.replace(api_key, "[REDACTED]") if api_key else message.content}],
    } for message in messages], separators=(",", ":"), ensure_ascii=False)


def _output_messages(payload: dict) -> str:
    """Represent a structured API result using Splunk's native workflow output."""
    content = json.dumps(payload, separators=(",", ":"), ensure_ascii=False)
    return json.dumps([{
        "role": "assistant", "parts": [{"type": "text", "content": content}], "finish_reason": "unknown",
    }], separators=(",", ":"), ensure_ascii=False)


def _inspection_output(response, api_key: str) -> str:
    """Copy only the pinned SDK response schema; bound the complete OTel value."""
    truncated = False

    def value(source, name):
        return source.get(name) if isinstance(source, dict) else getattr(source, name, None)

    def scalar(item):
        nonlocal truncated
        if isinstance(item, Enum):
            item = item.value
        if isinstance(item, str):
            # The API key is never useful response content, including if echoed.
            text = item.replace(api_key, "[REDACTED]") if api_key else item
            encoded = text.encode("utf-8")
            if len(encoded) > 2048:
                truncated = True
                text = encoded[:2048].decode("utf-8", errors="ignore")
            return text
        if isinstance(item, bool) or isinstance(item, int) and -(2 ** 63) <= item < 2 ** 63:
            return item
        if item is not None:
            truncated = True
        return None

    def scalar_list(items):
        nonlocal truncated
        if not isinstance(items, (list, tuple)):
            if items is not None:
                truncated = True
            return None
        if len(items) > 32:
            truncated = True
        return [normalized for item in items[:32] if (normalized := scalar(item)) is not None]

    def fields(source, names):
        return {name: normalized for name in names if (normalized := scalar(value(source, name))) is not None}

    def objects(items, names, *, entity_types=False):
        nonlocal truncated
        if not isinstance(items, (list, tuple)):
            if items is not None:
                truncated = True
            return None
        if len(items) > 32:
            truncated = True
        result = []
        for item in items[:32]:
            entry = fields(item, names)
            if entity_types and (entities := scalar_list(value(item, "entity_types"))) is not None:
                entry["entity_types"] = entities
            result.append(entry)
        return result

    payload = fields(response, (
        "is_safe", "action", "severity", "attack_technique", "explanation", "client_transaction_id", "event_id",
    ))
    if (classifications := scalar_list(value(response, "classifications"))) is not None:
        payload["classifications"] = classifications
    for name in ("rules", "processed_rules"):
        entries = objects(value(response, name), ("rule_name", "rule_id", "classification", "profile_id"), entity_types=True)
        if entries is not None:
            payload[name] = entries
    if (pii := objects(value(response, "detected_pii"), ("message_index", "type", "start_index", "end_index"))) is not None:
        payload["detected_pii"] = pii
    if truncated:
        payload["truncated"] = True
    output = _output_messages(payload)
    while len(output.encode("utf-8")) > MAX_INSPECTION_OUTPUT_BYTES:
        # Preserve the decision and IDs while trimming evaluated rules first.
        payload["truncated"] = True
        for name in ("processed_rules", "rules", "detected_pii", "classifications"):
            if payload.get(name):
                payload[name].pop()
                break
        else:
            # Strings are already individually bounded; halve the longest first.
            name = max((key for key, item in payload.items() if isinstance(item, str) and item),
                       key=lambda key: len(payload[key].encode("utf-8")))
            encoded = payload[name].encode("utf-8")
            payload[name] = encoded[:len(encoded) // 2].decode("utf-8", errors="ignore")
        output = _output_messages(payload)
    return output


def _dialogue_messages(messages: list[dict]) -> list[dict[str, str]]:
    """Only conversation dialogue may cross the Cisco inspection boundary."""
    return [item for item in text_messages(messages) if item["role"] in {"user", "assistant"}]


class IsolatedCiscoConfig(Config):
    """Give this app a fresh Config so rotated origins bypass the SDK singleton."""

    def __new__(cls, *args, **kwargs):
        return object.__new__(cls)


def make_client(secret: dict) -> ChatInspectionClient:
    silent = logging.getLogger("agentcore_chat.cisco_transport")
    silent.disabled = True
    sdk_config = IsolatedCiscoConfig(
        runtime_base_url=secret["inspection_origin"], timeout=3,
        logger=silent, retry_config={"total": 0},
    )
    return ChatInspectionClient(api_key=secret["api_key"], config=sdk_config)


class CiscoMonitor(HookProvider):
    def __init__(self, request: ChatRequest, secret: dict | None, tracer, *, client_factory=None):
        self.request = request
        self.secret = secret
        self.tracer = tracer
        self.status = "unconfigured" if secret is None else "ok"
        self.inspection_ids: list[str] = []
        self._client = None
        self._client_factory = client_factory or make_client
        self._input_messages: tuple[tuple[str, str], ...] | None = None

    def register_hooks(self, registry: HookRegistry, **kwargs) -> None:
        registry.add_callback(BeforeModelCallEvent, self.before_model)
        registry.add_callback(AfterModelCallEvent, self.after_model)

    async def before_model(self, event: BeforeModelCallEvent) -> None:
        if self.secret is None:
            return
        try:
            messages = _dialogue_messages(event.agent.messages)
            # The hook belongs to a fresh per-request agent. Retain immutable text
            # values so later history changes cannot alter the inspected input.
            self._input_messages = tuple((item["role"], item["content"]) for item in messages)
            await asyncio.to_thread(self.inspect, "input", messages)
        except Exception as error:
            self._hook_error("input", error)

    async def after_model(self, event: AfterModelCallEvent) -> None:
        if self.secret is None:
            return
        try:
            if event.stop_response is not None and self._input_messages is not None:
                messages = [{"role": role, "content": content} for role, content in self._input_messages]
                # AfterModelCallEvent runs before Strands appends this response.
                messages.extend(_dialogue_messages([event.stop_response.message]))
                await asyncio.to_thread(self.inspect, "output", messages)
        except Exception as error:
            self._hook_error("output", error)

    def _hook_error(self, phase: str, error: Exception) -> None:
        # Normalization and tracing failures share the monitor-only boundary too.
        self.status = "error"
        diagnostic("integration_error", self.request.request_id, integration="cisco", phase=phase,
                   status="error", errorCode=safe_error_code(error))

    def _capture_output(self, span, response=None, *, error_code: str | None = None) -> None:
        if not CAPTURE_CONTENT.get():
            return
        try:
            output = (_output_messages({"inspection_status": "error", "error_type": error_code})
                      if error_code is not None else _inspection_output(response, self.secret["api_key"]))
            span.set_attribute("gen_ai.output.messages", output)
        except Exception as error:
            # Telemetry formatting must not change an inspection's outcome.
            diagnostic("integration_error", self.request.request_id, integration="splunk", phase="cisco_output",
                       status="error", errorCode=safe_error_code(error))

    def _capture_input(self, span, messages: list[Message]) -> None:
        if not CAPTURE_CONTENT.get():
            return
        try:
            span.set_attribute("gen_ai.input.messages", _inspection_input(messages, self.secret["api_key"]))
        except Exception as error:
            # A telemetry failure must never prevent the inspection from running.
            diagnostic("integration_error", self.request.request_id, integration="splunk", phase="cisco_input",
                       status="error", errorCode=safe_error_code(error))

    def inspect(self, phase: str, messages: list[dict[str, str]]) -> None:
        if self.secret is None:
            return
        started = time.monotonic()
        inspection_request_id = str(uuid4())
        with self.tracer.start_as_current_span("cisco.inspect", record_exception=False, set_status_on_exception=False) as span:
            span.set_attributes({
                "cisco.mode": "monitor", "cisco.phase": phase,
                "gen_ai.operation.name": "invoke_workflow", "gen_ai.workflow.name": "cisco.inspect",
                "app.request.id": self.request.request_id,
                "gen_ai.conversation.id": self.request.conversation_id,
                "cisco.request.id": inspection_request_id,
            })
            try:
                # Reuse the same normalized dialogue for inspection and tracing.
                inspection_messages = [Message(role=Role(item["role"]), content=item["content"])
                                       for item in _dialogue_messages(messages)]
                self._capture_input(span, inspection_messages)
                if self._client is None:
                    self._client = self._client_factory(self.secret)
                result = self._client.inspect_conversation(
                    # Enforce the role allowlist again at the final SDK boundary.
                    messages=inspection_messages,
                    metadata=Metadata(
                        user=self.request.user_id, src_app="agentcore-chat-lab",
                        dst_app="amazon-bedrock", client_transaction_id=self.request.request_id,
                    ),
                    request_id=inspection_request_id, policy_id=self.secret.get("policy_id"), timeout=3,
                )
                classifications = [str(getattr(value, "value", value)) for value in result.classifications or []]
                inspection_id = result.event_id or inspection_request_id
                self.inspection_ids.append(inspection_id)
                safe = bool(result.is_safe)
                if not safe and self.status != "error":
                    self.status = "findings"
                span.set_attributes({
                    "cisco.is_safe": safe,
                    "cisco.inspection.id": inspection_id,
                    "cisco.classifications": classifications,
                    "cisco.classification_count": len(classifications),
                })
                diagnostic("cisco_inspection", self.request.request_id, phase=phase,
                           status="ok" if safe else "findings", inspectionId=inspection_id,
                           traceId=format(span.get_span_context().trace_id, "032x"),
                           classificationCount=len(classifications),
                           latencyMs=round((time.monotonic() - started) * 1000))
                self._capture_output(span, result)
            except Exception as error:
                # Monitor-only mode is an intentional fail-open boundary.
                self.status = "error"
                code = safe_error_code(error)
                span.set_attribute("error.type", code)
                span.set_status(Status(StatusCode.ERROR, "Cisco inspection failed"))
                self._capture_output(span, error_code=code)
                diagnostic("integration_error", self.request.request_id, integration="cisco", phase=phase,
                           status="error", errorCode=code,
                           latencyMs=round((time.monotonic() - started) * 1000))
