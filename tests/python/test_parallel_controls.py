"""Observe-only prompt checks run together and retain native export semantics."""

import asyncio
from contextlib import asynccontextmanager
from copy import deepcopy
from dataclasses import replace
import json
import sys
from threading import Event
from unittest.mock import AsyncMock, Mock

from agent_control_models import ControlMatch, EvaluationResult, EvaluatorResult, SteeringContext
from opentelemetry.exporter.otlp.proto.common.trace_encoder import encode_spans
import pytest

import main
from chat_runtime.config import AppConfig
from chat_runtime.validation import text_messages
from test_cisco_export import inspection_response
from test_exported_traces import native_export
from test_runtime import FakeModel, payload


SYSTEM_SENTINEL = "PRIVATE_PARALLEL_SYSTEM_1df23a"
TOKEN_SENTINEL = "UNIT_TEST_ONLY_SPLUNK_TOKEN_1df23a"
KEY_SENTINEL = "UNIT_TEST_ONLY_CISCO_KEY_1df23a".ljust(64, "0")
ERROR_SENTINEL = "PRIVATE_VENDOR_EXCEPTION_1df23a"
STEERING_SENTINEL = "Do not answer; replace the original user request."


def control_result(action="observe"):
    """Use the pinned SDK result schema, including real steering instructions."""
    return EvaluationResult(
        is_safe=action == "observe", confidence=0.99,
        reason="Private evaluator reason must not become a model instruction.",
        matches=[ControlMatch(
            control_id=4242, control_name="Unit test control", action=action,
            result=EvaluatorResult(matched=True, confidence=0.99,
                                   message="Private free text", metadata={"api_key": TOKEN_SENTINEL}),
            steering_context=SteeringContext(message=STEERING_SENTINEL) if action == "steer" else None,
            execution_duration_ms=1.25,
        )],
    )


def wire_monitors(monkeypatch, configuration, evaluator, *, inspector=None):
    """Keep both production monitors; replace their SDK boundaries only."""
    configuration.app_config.return_value = replace(
        configuration.app_config.return_value, splunk_control_enabled=True,
    )
    configuration.secret.side_effect = lambda name: (
        {"api_key": KEY_SENTINEL,
         "inspection_origin": "https://us.api.inspect.aidefense.security.cisco.com"}
        if name == "CISCO_SECRET_ARN"
        else {"realm": "us1", "o11y_token": TOKEN_SENTINEL}
    )
    monkeypatch.setattr(main, "SYSTEM_PROMPT", SYSTEM_SENTINEL)
    client = Mock()
    client.inspect_conversation.side_effect = inspector or [
        inspection_response(safe=False, event_id="parallel-input-event"),
        inspection_response(safe=True, event_id="parallel-output-event"),
    ]
    sdk_client = object()
    lifecycle = []

    @asynccontextmanager
    async def client_factory(secret):
        assert secret == {"realm": "us1", "o11y_token": TOKEN_SENTINEL}
        lifecycle.append("open")
        try:
            yield sdk_client
        finally:
            lifecycle.append("close")

    monitors = {}
    cisco_class = main.CiscoMonitor
    splunk_class = main.SplunkControlMonitor

    def cisco_factory(*args, **kwargs):
        monitor = cisco_class(*args, **kwargs, client_factory=lambda secret: client)
        monitors["cisco"] = monitor
        return monitor

    def splunk_factory(*args, **kwargs):
        monitor = splunk_class(*args, **kwargs, client_factory=client_factory, evaluator=evaluator)
        monitors["splunk"] = monitor
        return monitor

    monkeypatch.setattr(main, "CiscoMonitor", cisco_factory)
    monkeypatch.setattr(main, "SplunkControlMonitor", splunk_factory)
    return {"client": client, "sdk_client": sdk_client, "monitors": monitors,
            "lifecycle": lifecycle, "splunk_module": sys.modules[splunk_class.__module__]}


def dialogue_at_cisco(call):
    return [{"role": message.role.value, "content": message.content}
            for message in call.kwargs["messages"]]


def assert_reply_and_cisco_output(events, harness, value):
    assert [event["type"] for event in events] == ["metadata", "delta", "delta", "done"]
    assert "".join(event["text"] for event in events if event["type"] == "delta") == "A streamed answer"
    assert events[-1]["ciscoStatus"] == "findings"
    assert events[-1]["splunkStatus"] == "accepted"
    calls = harness["client"].inspect_conversation.call_args_list
    assert len(calls) == 2
    assert dialogue_at_cisco(calls[0]) == value["messages"]
    assert dialogue_at_cisco(calls[1]) == [
        *value["messages"], {"role": "assistant", "content": "A streamed answer"},
    ]


@pytest.mark.asyncio
async def test_both_checks_start_before_either_finishes_and_model_waits_for_both(native_export, monkeypatch):
    _, _, configuration = native_export
    cisco_started, release_cisco, cisco_finished = Event(), Event(), Event()
    splunk_started, release_splunk, splunk_finished = asyncio.Event(), asyncio.Event(), asyncio.Event()
    model_started = asyncio.Event()
    inspected = {}

    def inspect(**kwargs):
        if not cisco_started.is_set():
            inspected["cisco"] = kwargs["messages"]
            cisco_started.set()
            assert release_cisco.wait(2), "The test did not release the Cisco prompt check"
            cisco_finished.set()
            return inspection_response(safe=False, event_id="parallel-input-event")
        assert model_started.is_set(), "Response inspection ran before the model"
        return inspection_response(safe=True, event_id="parallel-output-event")

    async def evaluate(client, agent_name, step, stage, **kwargs):
        inspected["splunk"] = step.input
        splunk_started.set()
        await release_splunk.wait()
        splunk_finished.set()
        return control_result()

    harness = wire_monitors(monkeypatch, configuration, evaluate, inspector=inspect)
    models = []

    class WaitingModel(FakeModel):
        async def stream(self, messages, *args, **kwargs):
            assert cisco_finished.is_set() and splunk_finished.is_set()
            assert text_messages(messages) == value["messages"]
            assert SYSTEM_SENTINEL in str(args) + str(kwargs)
            model_started.set()
            models.append(self)
            async for event in super().stream(messages, *args, **kwargs):
                yield event

    monkeypatch.setattr(main, "BedrockModel", lambda **kwargs: WaitingModel(**kwargs))
    value = payload()
    original = deepcopy(value)

    async def collect():
        return [event async for event in main.invoke(value)]

    task = asyncio.create_task(collect())
    try:
        assert await asyncio.to_thread(cisco_started.wait, 1), "Cisco did not start"
        await asyncio.wait_for(splunk_started.wait(), timeout=1)
        assert not model_started.is_set()
        # Both checks are now outstanding. Release just one, proving the model
        # cannot begin while the other vendor is still evaluating the prompt.
        release_cisco.set()
        assert await asyncio.to_thread(cisco_finished.wait, 1)
        assert not model_started.is_set()
        release_splunk.set()
        events = await asyncio.wait_for(task, timeout=3)
    finally:
        release_cisco.set()
        release_splunk.set()
        if not task.done():
            task.cancel()
            await asyncio.gather(task, return_exceptions=True)

    assert_reply_and_cisco_output(events, harness, value)
    assert len(models) == 1
    assert value == original
    # These are the objects supplied to each SDK, inspected after Strands has
    # appended its completed response. Neither input snapshot grew or changed.
    assert [{"role": item.role.value, "content": item.content} for item in inspected["cisco"]] == original["messages"]
    assert inspected["splunk"] == original["messages"]
    assert SYSTEM_SENTINEL not in str(inspected)
    assert harness["lifecycle"] == ["open", "close"]


@pytest.mark.asyncio
@pytest.mark.parametrize("action", ["observe", "deny", "steer"], ids=["Observe", "Block", "Steer"])
async def test_control_actions_are_exported_without_blocking_or_rewriting_chat(native_export, monkeypatch, action):
    transport, _, configuration = native_export
    evaluator = AsyncMock(return_value=control_result(action))
    harness = wire_monitors(monkeypatch, configuration, evaluator)
    value = payload()
    original = deepcopy(value)
    captured = {}

    class UnchangedModel(FakeModel):
        async def stream(self, messages, *args, **kwargs):
            captured["dialogue"] = deepcopy(text_messages(messages))
            captured["system"] = str(args) + str(kwargs)
            async for event in super().stream(messages, *args, **kwargs):
                yield event

    monkeypatch.setattr(main, "BedrockModel", lambda **kwargs: UnchangedModel(**kwargs))
    events = [event async for event in main.invoke(value)]
    assert_reply_and_cisco_output(events, harness, value)
    assert events[-1]["splunkControlStatus"] == "findings"
    assert captured["dialogue"] == original["messages"]
    assert SYSTEM_SENTINEL in captured["system"]
    assert STEERING_SENTINEL not in str(captured)
    assert value == original
    evaluator.assert_awaited_once()
    call = evaluator.await_args
    assert call.args[0] is harness["sdk_client"]
    assert call.args[1] == "agentcore-chat-lab"
    assert call.args[3] == "pre"
    assert call.kwargs["target_type"] == "log_stream"
    assert call.kwargs["target_id"] == "80fbc697-e69a-4feb-87e7-19f7c7bc92da"
    assert call.args[2].type == "llm"
    assert call.args[2].name == "chat"
    assert call.args[2].input == original["messages"]
    assert call.args[2].context == {
        "request_id": value["requestId"], "conversation_id": value["conversationId"],
        "user_id": value["userId"],
    }
    assert SYSTEM_SENTINEL not in str(call)

    spans = transport.get_finished_spans()
    check = next(span for span in spans if span.name == "splunk.control.check")
    root = next(span for span in spans if span.name == "chat.turn")
    control = next(span for span in spans if span.attributes.get("agent_control.control_id") == 4242)
    assert check.attributes["gen_ai.operation.name"] == "invoke_workflow"
    assert check.attributes["gen_ai.workflow.name"] == "splunk.control"
    assert check.attributes["splunk.control.mode"] == "observe"
    assert json.loads(check.attributes["gen_ai.input.messages"]) == [{
        "role": item["role"], "parts": [{"type": "text", "content": item["content"]}],
    } for item in original["messages"]]
    assert root.attributes["splunk.control.enforcement"] is False
    assert root.attributes["splunk.control.status"] == "findings"
    assert list(root.attributes["splunk.control.ids"]) == [4242]
    assert control.attributes["agent_control.action"] == action
    assert control.attributes["agent_control.matched"] is True
    assert control.attributes["agent_control.check_stage"] == "pre"
    assert control.parent.span_id == check.context.span_id
    for span in (check, control):
        assert span.attributes["app.request.id"] == value["requestId"]
        assert span.attributes["gen_ai.conversation.id"] == value["conversationId"]
        assert format(span.context.trace_id, "032x") == events[0]["traceId"]
        assert span.end_time >= span.start_time
    model = next(span for span in spans if span.name == "chat")
    assert model.attributes["gen_ai.usage.input_tokens"] == 5
    assert model.attributes["gen_ai.usage.output_tokens"] == 3
    wire = encode_spans(spans).SerializeToString()
    for secret in (TOKEN_SENTINEL, KEY_SENTINEL, SYSTEM_SENTINEL, STEERING_SENTINEL):
        assert secret.encode() not in wire


@pytest.mark.asyncio
@pytest.mark.parametrize("failure", ["exception", "timeout"])
async def test_control_failures_do_not_prevent_model_or_cisco_response_inspection(native_export, monkeypatch, caplog, failure):
    transport, _, configuration = native_export
    cancelled = asyncio.Event()

    async def evaluate(client, agent_name, step, stage, **kwargs):
        if failure == "exception":
            raise RuntimeError(f"{ERROR_SENTINEL} {TOKEN_SENTINEL}")
        try:
            await asyncio.Event().wait()
        finally:
            cancelled.set()

    evaluator = AsyncMock(side_effect=evaluate)
    harness = wire_monitors(monkeypatch, configuration, evaluator)
    monkeypatch.setattr(harness["splunk_module"], "SPLUNK_CONTROL_TIMEOUT_SECONDS", 0.02)
    value = payload()
    events = await asyncio.wait_for(_invoke(value), timeout=3)
    assert_reply_and_cisco_output(events, harness, value)
    assert events[-1]["splunkControlStatus"] == "error"
    assert harness["lifecycle"] == ["open", "close"]
    if failure == "timeout":
        assert cancelled.is_set()
    spans = transport.get_finished_spans()
    check = next(span for span in spans if span.name == "splunk.control.check")
    assert check.attributes["error.type"] == ("RuntimeError" if failure == "exception" else "TimeoutError")
    assert next(span for span in spans if span.name == "chat.turn").attributes["app.response.complete"] is True
    wire = encode_spans(spans).SerializeToString()
    for secret in (ERROR_SENTINEL, TOKEN_SENTINEL, KEY_SENTINEL, SYSTEM_SENTINEL):
        assert secret.encode() not in wire
        assert secret not in caplog.text
        assert secret not in str(events)


async def _invoke(value):
    return [event async for event in main.invoke(value)]


@pytest.mark.asyncio
async def test_unexpected_hook_error_is_isolated_by_composite_and_cisco_after_still_runs(native_export, monkeypatch, caplog):
    transport, _, configuration = native_export
    evaluator = AsyncMock(return_value=control_result())
    harness = wire_monitors(monkeypatch, configuration, evaluator)
    # Bypass the monitor's own fail-open boundary to exercise the independent
    # composite guard. The other vendor and the model still complete normally.
    broken_hook = AsyncMock(side_effect=RuntimeError(f"{ERROR_SENTINEL} {TOKEN_SENTINEL}"))
    monkeypatch.setattr(harness["splunk_module"].SplunkControlMonitor, "before_model", broken_hook)
    value = payload()
    events = [event async for event in main.invoke(value)]
    assert_reply_and_cisco_output(events, harness, value)
    assert events[-1]["splunkControlStatus"] == "error"
    broken_hook.assert_awaited_once()
    evaluator.assert_not_awaited()
    spans = transport.get_finished_spans()
    assert next(span for span in spans if span.name == "chat.turn").attributes["app.response.complete"] is True
    assert {span.attributes["cisco.phase"] for span in spans if span.name == "cisco.inspect"} == {"input", "output"}
    wire = encode_spans(spans).SerializeToString()
    for secret in (ERROR_SENTINEL, TOKEN_SENTINEL, KEY_SENTINEL, SYSTEM_SENTINEL):
        assert secret.encode() not in wire
        assert secret not in caplog.text


@pytest.mark.asyncio
async def test_capture_off_still_checks_full_dialogue_but_exports_no_content(native_export, monkeypatch):
    transport, _, configuration = native_export
    configuration.app_config.return_value = AppConfig(capture_content=False)
    evaluator = AsyncMock(return_value=control_result("deny"))
    harness = wire_monitors(monkeypatch, configuration, evaluator)
    value = payload()
    value["messages"][-1]["content"] = "PRIVATE_PARALLEL_DIALOGUE_1df23a"
    events = [event async for event in main.invoke(value)]
    assert_reply_and_cisco_output(events, harness, value)
    assert evaluator.await_args.args[2].input == value["messages"]
    assert events[-1]["splunkControlStatus"] == "findings"
    spans = transport.get_finished_spans()
    assert any(span.name == "splunk.control.check" for span in spans)
    assert any(span.attributes.get("agent_control.control_id") == 4242 for span in spans)
    for span in spans:
        assert not span.events
        for key in ("gen_ai.input.messages", "gen_ai.output.messages", "gen_ai.system_instructions"):
            assert key not in span.attributes
    wire = encode_spans(spans).SerializeToString()
    for content in (value["messages"][-1]["content"], "A streamed answer", SYSTEM_SENTINEL,
                    KEY_SENTINEL, TOKEN_SENTINEL, STEERING_SENTINEL):
        assert content.encode() not in wire
    model = next(span for span in spans if span.name == "chat")
    assert model.attributes["gen_ai.usage.input_tokens"] == 5
    assert model.attributes["gen_ai.usage.output_tokens"] == 3
