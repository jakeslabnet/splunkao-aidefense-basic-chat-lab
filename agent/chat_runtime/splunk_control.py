"""Explicit Splunk server checks that report decisions without enforcing them."""

import asyncio
from contextlib import contextmanager
import json
import logging
import math
import time
from uuid import UUID

from agent_control import AgentControlClient
from agent_control_models import EvaluationRequest, EvaluationResult, Step
from httpx import HTTPStatusError
from opentelemetry.trace import INVALID_SPAN, Status, StatusCode, get_current_span
from splunk_ao.converter import build_span_attributes
from splunk_ao.logger.control import ControlResult, ControlSpan

from .diagnostics import diagnostic, safe_error_code
from .telemetry import CAPTURE_CONTENT
from .validation import ChatRequest, text_messages


TARGET_TYPE = "log_stream"
TARGET_ID = "80fbc697-e69a-4feb-87e7-19f7c7bc92da"
AGENT_NAME = "agentcore-chat-lab"
SPLUNK_CONTROL_TIMEOUT_SECONDS = 15.0
MAX_CONTROL_RESULTS = 32
MAX_CONTROL_OUTPUT_BYTES = 16 * 1024
_ACTIONS = {"observe", "deny", "steer"}


def _quiet_sdk_logs() -> None:
    # SDK error/debug records can contain full evaluation bodies or credentials.
    # Only this application's allowlisted diagnostic records are retained.
    for name in ("agent_control", "agent_control_engine", "agent_control_evaluators", "agent_control_telemetry"):
        logger = logging.getLogger(name)
        logger.handlers.clear()
        logger.addHandler(logging.NullHandler())
        logger.propagate = False


_quiet_sdk_logs()


def make_client(secret: dict) -> AgentControlClient:
    """Create credentials and sockets only while handling a restored request."""
    if secret.get("realm") != "us1" or not isinstance(secret.get("o11y_token"), str) or not secret["o11y_token"]:
        raise ValueError("Invalid Splunk control configuration")
    # Splunk's API-domain mapping and AO's SaaS Agent Control route are fixed;
    # no caller-controlled URL can receive the bootstrap credential.
    return AgentControlClient(
        base_url="https://api.us1.observability.splunkcloud.com/ao/agent-control",
        api_key=secret["o11y_token"], api_key_header="X-SF-Token",
        runtime_auth_mode="jwt", runtime_token_header="X-Agent-Control-Runtime-Token",
        timeout=12.0,
    )


async def evaluate_server_control(client, agent_name, step, stage, *, target_type, target_id):
    """Use the SDK's JWT-aware evaluation API without its global event sinks.

    The higher-level check_evaluation helper can initialize an event sink from
    global SDK settings. We own trace export, so use the public client API and
    shared request/result models instead. No registration or action is applied.
    """
    request = EvaluationRequest(
        agent_name=agent_name, step=step, stage=stage,
        target_type=target_type, target_id=target_id,
    )
    headers = None
    try:
        span = get_current_span()
        context = span.get_span_context()
        # Use the application's active span, never generated fallback IDs or
        # a remote context borrowed from an incoming request. Standalone
        # preflight calls have no application span and send neither header.
        if context.is_valid and not context.is_remote and span.is_recording():
            headers = {
                "X-Trace-Id": format(context.trace_id, "032x"),
                "X-Span-Id": format(context.span_id, "016x"),
            }
    except Exception:
        # Correlation failures must not skip the monitor's server evaluation.
        pass
    response = await client.post_runtime_evaluation(
        json=request.model_dump(mode="json"), headers=headers,
        target_type=target_type, target_id=target_id,
    )
    response.raise_for_status()
    return EvaluationResult.model_validate(response.json())


def _number(value):
    if type(value) in (int, float) and 0 <= value <= 1 and math.isfinite(value):
        return float(value)
    return None


def _execution_id(value, token):
    if not isinstance(value, str) or len(value) > 36 or value == token:
        return None
    try:
        return str(UUID(value))
    except (ValueError, AttributeError):
        return None


def summarize_result(result, token: str) -> dict:
    """Never retain free-text reasons, evaluator metadata, or steering content."""
    summary = {"mode": "observe", "enforced": False, "stage": "pre"}
    if type(result.is_safe) is not bool:
        raise ValueError("Invalid evaluation result")
    summary["is_safe"] = result.is_safe
    if (confidence := _number(result.confidence)) is not None:
        summary["confidence"] = confidence
    remaining = MAX_CONTROL_RESULTS
    summary["match_count"] = 0
    summary["error_count"] = 0
    for group in ("matches", "errors", "non_matches"):
        items = getattr(result, group, None) or []
        if not isinstance(items, (list, tuple)):
            raise ValueError("Invalid evaluation group")
        if group == "matches":
            summary["match_count"] = len(items)
        summary["error_count"] += sum(bool(item.result.error) or group == "errors" for item in items)
        summary[group] = []
        for item in items[:remaining]:
            entry = {}
            if type(item.control_id) is int and 0 <= item.control_id < 2 ** 63:
                entry["control_id"] = item.control_id
            if (execution_id := _execution_id(item.control_execution_id, token)) is not None:
                entry["control_execution_id"] = execution_id
            action = getattr(item.action, "value", item.action)
            if isinstance(action, str) and action in _ACTIONS:
                entry["action"] = action
            if type(item.result.matched) is bool:
                entry["matched"] = item.result.matched
            if (confidence := _number(item.result.confidence)) is not None:
                entry["confidence"] = confidence
            # Preserve only error presence: the service's error can echo inputs.
            entry["error"] = bool(item.result.error) or group == "errors"
            summary[group].append(entry)
        if len(items) > remaining:
            summary["truncated"] = True
        remaining -= len(summary[group])
    return summary


def _output_messages(payload: dict) -> str:
    return json.dumps([{
        "role": "assistant", "parts": [{"type": "text", "content": json.dumps(payload, separators=(",", ":"))}],
        "finish_reason": "unknown",
    }], separators=(",", ":"))


class SplunkControlMonitor:
    """A per-request monitor; no init, decorator, cancellation, or retry actions."""

    def __init__(self, request: ChatRequest, secret: dict | None, tracer, *, client_factory=None, evaluator=None):
        self.request = request
        self.secret = secret
        self.tracer = tracer
        self.status = "unconfigured" if secret is None else "ok"
        self.control_ids: list[int] = []
        self.results: dict = {}
        self._client_factory = client_factory or make_client
        self._evaluator = evaluator or evaluate_server_control

    def _telemetry_error(self, error):
        diagnostic("integration_error", self.request.request_id, integration="splunk_control", phase="telemetry",
                   status="error", errorCode=safe_error_code(error))

    @contextmanager
    def _span(self, name):
        # Tracing failure must not skip the check or escape to the model hook.
        manager = None
        span = INVALID_SPAN
        try:
            manager = self.tracer.start_as_current_span(name, record_exception=False, set_status_on_exception=False)
            span = manager.__enter__()
        except Exception as error:
            manager = None
            self._telemetry_error(error)
        try:
            yield span
        finally:
            if manager is not None:
                try:
                    manager.__exit__(None, None, None)
                except Exception as error:
                    self._telemetry_error(error)

    def _attributes(self, span, values):
        try:
            span.set_attributes(values)
        except Exception as error:
            self._telemetry_error(error)

    def _capture(self, span, field, value):
        if CAPTURE_CONTENT.get():
            self._attributes(span, {field: value})

    def _capture_output(self, span, payload):
        if not CAPTURE_CONTENT.get():
            return
        try:
            output = _output_messages(payload)
            if len(output.encode("utf-8")) > MAX_CONTROL_OUTPUT_BYTES:
                raise ValueError("Control summary exceeds telemetry limit")
            self._capture(span, "gen_ai.output.messages", output)
        except Exception as error:
            self._telemetry_error(error)

    def _record_controls(self, summary):
        for group in ("matches", "errors", "non_matches"):
            for item in summary.get(group, []):
                control_id = item.get("control_id")
                with self._span("splunk.control.result") as span:
                    native = ControlSpan(
                        name="splunk.control.result", input="", control_id=control_id,
                        agent_name=AGENT_NAME, check_stage="pre", applies_to="llm_call",
                        output=ControlResult(
                            action=item.get("action", "observe"), matched=item.get("matched", False),
                            confidence=item.get("confidence"),
                            error_message="EvaluationError" if item["error"] else None,
                        ),
                    )
                    attributes = build_span_attributes(native, self.request.conversation_id)
                    # These native content fields are optional even for control spans.
                    attributes.pop("gen_ai.input.messages", None)
                    attributes.pop("gen_ai.output.messages", None)
                    attributes.update({
                        "app.request.id": self.request.request_id,
                        "splunk.control.mode": "observe", "splunk.control.enforced": False,
                    })
                    if "control_execution_id" in item:
                        attributes["agent_control.control_execution_id"] = item["control_execution_id"]
                    self._attributes(span, attributes)
                    self._capture_output(span, item)

    async def before_model(self, event) -> None:
        if self.secret is None:
            return
        started = time.monotonic()
        with self._span("splunk.control.check") as span:
            self._attributes(span, {
                "gen_ai.operation.name": "invoke_workflow", "gen_ai.workflow.name": "splunk.control",
                "app.request.id": self.request.request_id, "gen_ai.conversation.id": self.request.conversation_id,
                "splunk.control.mode": "observe", "splunk.control.enforced": False,
                "agent_control.agent_name": AGENT_NAME, "agent_control.check_stage": "pre",
                "agent_control.applies_to": "llm_call", "agent_control.target_type": TARGET_TYPE,
                "agent_control.target_id": TARGET_ID,
            })
            try:
                # text_messages copies text blocks; system/developer roles never
                # enter the evaluation payload or control telemetry.
                messages = [item for item in text_messages(event.agent.messages) if item["role"] in {"user", "assistant"}]
                if not messages:
                    raise ValueError("Missing evaluation dialogue")
                token = self.secret["o11y_token"]
                if CAPTURE_CONTENT.get():
                    try:
                        self._capture(span, "gen_ai.input.messages", json.dumps([{
                            "role": item["role"], "parts": [{"type": "text", "content": item["content"].replace(token, "[REDACTED]")}],
                        } for item in messages], separators=(",", ":"), ensure_ascii=False))
                    except Exception as error:
                        self._telemetry_error(error)
                async with asyncio.timeout(SPLUNK_CONTROL_TIMEOUT_SECONDS):
                    async with self._client_factory(self.secret) as client:
                        result = await self._evaluator(
                            client, AGENT_NAME, Step(type="llm", name="chat", input=messages, context={
                                "request_id": self.request.request_id,
                                "conversation_id": self.request.conversation_id,
                                "user_id": self.request.user_id,
                            }), "pre",
                            target_type=TARGET_TYPE, target_id=TARGET_ID,
                        )
                self.results = summarize_result(result, token)
                self.control_ids = sorted({item["control_id"] for group in ("matches", "errors", "non_matches")
                                           for item in self.results[group] if "control_id" in item})
                self.status = ("error" if self.results["error_count"] else "findings"
                               if self.results["match_count"] or not self.results["is_safe"] else "ok")
                self._attributes(span, {
                    "splunk.control.status": self.status, "splunk.control.is_safe": self.results["is_safe"],
                    "splunk.control.match_count": self.results["match_count"],
                    "splunk.control.error_count": self.results["error_count"],
                    "splunk.control.actions": sorted({item["action"] for group in ("matches", "errors", "non_matches")
                                                      for item in self.results[group] if "action" in item}),
                })
                try:
                    self._record_controls(self.results)
                    self._capture_output(span, self.results)
                except Exception as error:
                    self._telemetry_error(error)
            except asyncio.CancelledError:
                self.status = "error"
                self._attributes(span, {"splunk.control.status": "cancelled", "error.type": "CancelledError"})
                raise
            except Exception as error:
                self.status = "error"
                code = safe_error_code(error)
                self.results = {"mode": "observe", "enforced": False, "status": "error", "error_type": code}
                self._attributes(span, {"splunk.control.status": "error", "error.type": code})
                if isinstance(error, HTTPStatusError) and 100 <= error.response.status_code <= 599:
                    self.results["http_status"] = error.response.status_code
                    self._attributes(span, {"http.response.status_code": error.response.status_code})
                    code = "HTTPStatus" + str(error.response.status_code)
                self._capture_output(span, self.results)
                diagnostic("integration_error", self.request.request_id, integration="splunk_control", phase="pre",
                           status="error", errorCode=code)
                try:
                    span.set_status(Status(StatusCode.ERROR, "Splunk control check failed"))
                except Exception as telemetry_error:
                    self._telemetry_error(telemetry_error)
            try:
                trace_id = format(span.get_span_context().trace_id, "032x")
            except Exception:
                trace_id = "0" * 32
            diagnostic("splunk_control_check", self.request.request_id, integration="splunk_control", phase="pre",
                       status=self.status, traceId=trace_id,
                       latencyMs=round((time.monotonic() - started) * 1000))
