import asyncio
from copy import deepcopy
import json
import logging
from types import SimpleNamespace
from uuid import uuid4

import agent_control
from agent_control_models import ControlMatch, EvaluationResult, EvaluatorResult, Step
import httpx
from opentelemetry.sdk.trace import TracerProvider
from opentelemetry.sdk.trace.export import SimpleSpanProcessor
from opentelemetry.sdk.trace.export.in_memory_span_exporter import InMemorySpanExporter
from opentelemetry.trace import INVALID_SPAN, NonRecordingSpan, SpanContext, use_span
import pytest
from strands.hooks import BeforeModelCallEvent

from chat_runtime import splunk_control as control
from chat_runtime.telemetry import CAPTURE_CONTENT
from chat_runtime.validation import ChatRequest


SECRET = {"realm": "us1", "o11y_token": "SECRET_INGEST_CANARY"}
EXECUTION_ID = "11111111-1111-4111-8111-111111111111"


def setup():
    request = ChatRequest(str(uuid4()), str(uuid4()), "a" * 64, [{"role": "user", "content": "Question"}])
    provider = TracerProvider()
    exporter = InMemorySpanExporter()
    provider.add_span_processor(SimpleSpanProcessor(exporter))
    event = BeforeModelCallEvent(agent=SimpleNamespace(messages=[
        {"role": "system", "content": "SYSTEM_PRIVATE_CANARY"},
        {"role": "developer", "content": "DEVELOPER_PRIVATE_CANARY"},
        {"role": "user", "content": [{"text": "First question"}]},
        {"role": "assistant", "content": [{"text": "Previous answer"}]},
        {"role": "user", "content": [{"text": "Next question"}]},
    ]))
    return request, provider.get_tracer("control-test"), exporter, event


def result(action="observe", *, error=None, count=1):
    return EvaluationResult(is_safe=False, confidence=0.9, reason="PRIVATE_REASON_CANARY", matches=[
        ControlMatch(control_execution_id=EXECUTION_ID, control_id=229 + i, control_name="PRIVATE_NAME_CANARY",
                     action=action, result=EvaluatorResult(matched=True, confidence=0.9,
                        error=error, message="PRIVATE_MESSAGE_CANARY", metadata={"private": "PRIVATE_METADATA_CANARY"}))
        for i in range(count)
    ])


class FakeClient:
    def __init__(self):
        self.closed = False

    async def __aenter__(self):
        return self

    async def __aexit__(self, *args):
        self.closed = True


@pytest.mark.asyncio
async def test_real_sdk_exchange_and_evaluation_use_fixed_target_and_only_typed_api(monkeypatch):
    request, tracer, exported, event = setup()
    calls = []

    async def respond(wire):
        calls.append(wire)
        assert wire.url.host == "api.us1.observability.splunkcloud.com"
        assert wire.headers["X-SF-Token"] == SECRET["o11y_token"]
        if wire.url.path.endswith("/auth/runtime-token-exchange"):
            assert "X-Agent-Control-Runtime-Token" not in wire.headers
            assert "X-Trace-Id" not in wire.headers and "X-Span-Id" not in wire.headers
            assert json.loads(wire.content) == {"target_type": "log_stream", "target_id": control.TARGET_ID}
            return httpx.Response(200, json={
                "token": "SYNTHETIC_RUNTIME_JWT", "expires_at": "2099-01-01T00:00:00Z",
                "target_type": "log_stream", "target_id": control.TARGET_ID, "scopes": ["evaluate"],
            })
        assert wire.url.path == "/ao/agent-control/api/v1/evaluation"
        assert wire.headers["X-Agent-Control-Runtime-Token"] == "SYNTHETIC_RUNTIME_JWT"
        assert "Authorization" not in wire.headers
        payload = json.loads(wire.content)
        assert payload["agent_name"] == "agentcore-chat-lab"
        assert payload["target_type"] == "log_stream" and payload["target_id"] == control.TARGET_ID
        assert payload["stage"] == "pre" and payload["step"]["type"] == "llm"
        assert payload["step"]["input"] == [
            {"role": "user", "content": "First question"},
            {"role": "assistant", "content": "Previous answer"},
            {"role": "user", "content": "Next question"},
        ]
        assert payload["step"]["context"] == {"request_id": request.request_id,
            "conversation_id": request.conversation_id, "user_id": request.user_id}
        return httpx.Response(200, json=result("deny").model_dump(mode="json"))

    real_client = control.AgentControlClient

    def injected_client(**kwargs):
        assert kwargs["runtime_auth_mode"] == "jwt" and kwargs["timeout"] == 12.0
        return real_client(**kwargs, transport=httpx.MockTransport(respond))

    monkeypatch.setattr(control, "AgentControlClient", injected_client)
    monkeypatch.setattr(agent_control, "init", lambda *args, **kwargs: pytest.fail("Global init is forbidden"))
    monitor = control.SplunkControlMonitor(request, SECRET, tracer)
    original = deepcopy(event.agent.messages)
    await monitor.before_model(event)
    assert len(calls) == 2
    assert monitor.status == "findings" and monitor.control_ids == [229]
    assert event.cancel is False and event.agent.messages == original
    assert agent_control.current_agent() is None
    rendered = repr([(s.name, dict(s.attributes), s.events) for s in exported.get_finished_spans()])
    assert SECRET["o11y_token"] not in rendered and "SYNTHETIC_RUNTIME_JWT" not in rendered
    assert "PRIVATE_" not in rendered
    child = next(s for s in exported.get_finished_spans() if s.name == "splunk.control.result")
    assert child.attributes["agent_control.action"] == "deny"
    assert child.attributes["agent_control.control_execution_id"] == EXECUTION_ID
    assert child.attributes["splunk.control.enforced"] is False
    workflow = next(s for s in exported.get_finished_spans() if s.name == "splunk.control.check")
    assert calls[1].headers["X-Trace-Id"] == format(workflow.context.trace_id, "032x")
    assert calls[1].headers["X-Span-Id"] == format(workflow.context.span_id, "016x")
    assert workflow.context.trace_id != 0 and workflow.context.span_id != 0


@pytest.mark.asyncio
@pytest.mark.parametrize("active_span", [
    INVALID_SPAN,
    NonRecordingSpan(SpanContext(trace_id=1, span_id=2, is_remote=True)),
    NonRecordingSpan(SpanContext(trace_id=1, span_id=2, is_remote=False)),
])
async def test_preflight_or_borrowed_context_never_generates_correlation_headers(active_span):
    calls = []

    async def respond(wire):
        calls.append(wire)
        assert "X-Trace-Id" not in wire.headers and "X-Span-Id" not in wire.headers
        assert "X-SF-Token" not in wire.headers and "Authorization" not in wire.headers
        return httpx.Response(200, json={"is_safe": True, "confidence": 1.0})

    async with control.AgentControlClient(
        base_url="https://api.us1.observability.splunkcloud.com/ao/agent-control",
        runtime_auth_mode="none", transport=httpx.MockTransport(respond),
    ) as client:
        with use_span(active_span):
            evaluated = await control.evaluate_server_control(
                client, control.AGENT_NAME, Step(type="llm", name="chat", input="Synthetic prompt"),
                "pre", target_type=control.TARGET_TYPE, target_id=control.TARGET_ID,
            )
    assert len(calls) == 1 and evaluated.is_safe is True


@pytest.mark.asyncio
@pytest.mark.parametrize("action", ["observe", "deny", "steer"])
async def test_all_actions_report_only_and_content_capture_can_be_disabled(action):
    request, tracer, exported, event = setup()
    client = FakeClient()

    async def evaluate(*args, **kwargs):
        return result(action)

    monitor = control.SplunkControlMonitor(request, SECRET, tracer,
        client_factory=lambda _: client, evaluator=evaluate)
    original = deepcopy(event.agent.messages)
    capture = CAPTURE_CONTENT.set(False)
    try:
        await monitor.before_model(event)
    finally:
        CAPTURE_CONTENT.reset(capture)
    assert monitor.status == "findings" and event.cancel is False
    assert event.agent.messages == original and client.closed
    spans = exported.get_finished_spans()
    assert {s.name for s in spans} == {"splunk.control.result", "splunk.control.check"}
    assert all("gen_ai.input.messages" not in s.attributes and "gen_ai.output.messages" not in s.attributes for s in spans)
    assert all(s.events == () for s in spans)


@pytest.mark.asyncio
async def test_timeout_closes_client_and_fails_open(monkeypatch):
    request, tracer, exported, event = setup()
    client = FakeClient()
    cancelled = asyncio.Event()

    async def evaluate(*args, **kwargs):
        try:
            await asyncio.Event().wait()
        finally:
            cancelled.set()

    monkeypatch.setattr(control, "SPLUNK_CONTROL_TIMEOUT_SECONDS", 0.01)
    monitor = control.SplunkControlMonitor(request, SECRET, tracer,
        client_factory=lambda _: client, evaluator=evaluate)
    await monitor.before_model(event)
    assert monitor.status == "error" and monitor.results["error_type"] == "TimeoutError"
    assert client.closed and cancelled.is_set() and event.cancel is False
    assert exported.get_finished_spans()[-1].attributes["error.type"] == "TimeoutError"


@pytest.mark.asyncio
async def test_parent_cancellation_propagates_without_enforcement():
    request, tracer, _, event = setup()
    client = FakeClient()
    started = asyncio.Event()

    async def evaluate(*args, **kwargs):
        started.set()
        await asyncio.Event().wait()

    monitor = control.SplunkControlMonitor(request, SECRET, tracer,
        client_factory=lambda _: client, evaluator=evaluate)
    task = asyncio.create_task(monitor.before_model(event))
    await started.wait()
    task.cancel()
    with pytest.raises(asyncio.CancelledError):
        await task
    assert client.closed and event.cancel is False and monitor.status == "error"


@pytest.mark.asyncio
async def test_http_permission_error_is_sanitized_and_never_retried_as_api_key(caplog, monkeypatch):
    request, tracer, exported, event = setup()
    calls = []

    async def forbidden(wire):
        calls.append(wire)
        return httpx.Response(403, text="PRIVATE_RESPONSE_CANARY " + SECRET["o11y_token"])

    real_client = control.AgentControlClient
    monkeypatch.setattr(control, "AgentControlClient", lambda **kwargs:
        real_client(**kwargs, transport=httpx.MockTransport(forbidden)))
    monitor = control.SplunkControlMonitor(request, SECRET, tracer)
    with caplog.at_level(logging.INFO, logger="agentcore_chat"):
        await monitor.before_model(event)
    assert len(calls) == 1 and calls[0].url.path.endswith("/auth/runtime-token-exchange")
    assert monitor.status == "error" and monitor.results["http_status"] == 403 and event.cancel is False
    assert "HTTPStatus403" in caplog.text
    rendered = caplog.text + repr([(dict(s.attributes), s.events) for s in exported.get_finished_spans()])
    assert SECRET["o11y_token"] not in rendered and "PRIVATE_RESPONSE_CANARY" not in rendered
    assert exported.get_finished_spans()[-1].attributes["http.response.status_code"] == 403


@pytest.mark.asyncio
async def test_tracing_failure_still_checks_and_retains_sanitized_result():
    request, _, _, event = setup()

    class BrokenTracer:
        def start_as_current_span(self, *args, **kwargs):
            raise RuntimeError("PRIVATE_TRACE_CANARY " + SECRET["o11y_token"])

    calls = []

    async def evaluate(*args, **kwargs):
        calls.append(args)
        return result("steer")

    monitor = control.SplunkControlMonitor(request, SECRET, BrokenTracer(),
        client_factory=lambda _: FakeClient(), evaluator=evaluate)
    await monitor.before_model(event)
    assert len(calls) == 1 and monitor.control_ids == [229]
    assert monitor.status == "findings" and event.cancel is False


def test_summary_bounds_results_drops_free_text_and_preserves_omitted_errors():
    evaluation = result(count=control.MAX_CONTROL_RESULTS + 4)
    evaluation.errors = [ControlMatch(control_id=999, control_name="PRIVATE_NAME_CANARY", action="observe",
        result=EvaluatorResult(matched=False, confidence=0.0, error="PRIVATE_ERROR_CANARY"))]
    summary = control.summarize_result(evaluation, SECRET["o11y_token"])
    assert sum(len(summary[g]) for g in ("matches", "errors", "non_matches")) == control.MAX_CONTROL_RESULTS
    assert summary["match_count"] == control.MAX_CONTROL_RESULTS + 4 and summary["error_count"] == 1
    assert summary["truncated"] is True and summary["enforced"] is False
    assert len(json.dumps(summary).encode()) < control.MAX_CONTROL_OUTPUT_BYTES
    assert "PRIVATE_" not in json.dumps(summary)


@pytest.mark.asyncio
async def test_unconfigured_skips_client_creation_and_config_rejects_other_realms():
    request, tracer, exported, event = setup()
    monitor = control.SplunkControlMonitor(request, None, tracer,
        client_factory=lambda _: pytest.fail("No credentials means no client"))
    await monitor.before_model(event)
    assert monitor.status == "unconfigured" and not exported.get_finished_spans() and event.cancel is False
    with pytest.raises(ValueError):
        control.make_client({"realm": "other.invalid", "o11y_token": SECRET["o11y_token"]})
