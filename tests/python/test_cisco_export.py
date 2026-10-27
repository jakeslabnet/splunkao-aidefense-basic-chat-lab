"""Cisco dialogue inputs and response JSON survive the native Splunk export."""

import json
from unittest.mock import Mock

from aidefense.runtime.models import Action, Classification, InspectResponse, Severity
from opentelemetry.exporter.otlp.proto.common.trace_encoder import encode_spans
from opentelemetry.trace import StatusCode
import pytest
from splunk_ao import WorkflowSpan
from splunk_ao.converter import build_span_attributes

import main
from chat_runtime.config import AppConfig
from test_exported_traces import native_export
from test_runtime import payload


SYSTEM_SENTINEL = "PRIVATE_SYSTEM_INSTRUCTIONS_14d8de"
KEY_SENTINEL = "PRIVATE_CISCO_KEY_14d8de".ljust(64, "0")


def inspection_response(*, safe, event_id, explanation="Inspection completed"):
    response = InspectResponse(
        is_safe=safe,
        classifications=[] if safe else [Classification.SAFETY_VIOLATION],
        action=Action.ALLOW if safe else Action.BLOCK,
        severity=Severity.NONE_SEVERITY if safe else Severity.HIGH,
        explanation=explanation,
        event_id=event_id,
    )
    # Unexpected vendor fields must never become exported response properties.
    response.api_key = KEY_SENTINEL
    response.system_instructions = SYSTEM_SENTINEL
    return response


def configure_inspections(monkeypatch, configuration, client):
    configuration.secret.side_effect = lambda name: (
        {"api_key": KEY_SENTINEL, "inspection_origin": "https://us.api.inspect.aidefense.security.cisco.com"}
        if name == "CISCO_SECRET_ARN"
        else {"realm": "us1", "o11y_token": "unit-test-placeholder"}
    )
    original = main.CiscoMonitor
    monkeypatch.setattr(main, "CiscoMonitor", lambda *args, **kwargs: original(
        *args, **kwargs, client_factory=lambda secret: client,
    ))
    monkeypatch.setattr(main, "SYSTEM_PROMPT", SYSTEM_SENTINEL)


def response_json(span):
    messages = json.loads(span.attributes["gen_ai.output.messages"])
    assert len(messages) == 1
    assert messages[0]["role"] == "assistant"
    assert len(messages[0]["parts"]) == 1
    assert messages[0]["parts"][0]["type"] == "text"
    content = messages[0]["parts"][0]["content"]
    expected = build_span_attributes(WorkflowSpan(name="cisco.inspect", output=content))
    expected_part = json.loads(expected["gen_ai.output.messages"])[0]["parts"][0]
    assert messages[0]["parts"][0]["type"] == expected_part["type"]
    assert json.loads(content) == json.loads(expected_part["content"])
    assert span.attributes["gen_ai.operation.name"] == expected["gen_ai.operation.name"] == "invoke_workflow"
    assert span.attributes["gen_ai.workflow.name"] == "cisco.inspect"
    parsed = json.loads(content)
    assert isinstance(parsed, dict)
    return parsed


def assert_input_matches_sdk_call(span, call):
    dialogue = [
        {"role": message.role.value, "content": message.content}
        for message in call.kwargs["messages"]
    ]
    expected = build_span_attributes(WorkflowSpan(name="cisco.inspect", input=dialogue))
    messages = json.loads(span.attributes["gen_ai.input.messages"])
    assert messages == json.loads(expected["gen_ai.input.messages"])
    assert all(message["role"] in {"user", "assistant"} for message in messages)
    assert KEY_SENTINEL not in span.attributes["gen_ai.input.messages"]
    assert SYSTEM_SENTINEL not in span.attributes["gen_ai.input.messages"]
    return dialogue


@pytest.mark.asyncio
async def test_each_cisco_phase_exports_exact_dialogue_input_and_response_output(native_export, monkeypatch):
    transport, _, configuration = native_export
    client = Mock()
    client.inspect_conversation.side_effect = [
        inspection_response(safe=False, event_id="input-vendor-event", explanation=f"Vendor echo {KEY_SENTINEL}"),
        inspection_response(safe=True, event_id="output-vendor-event"),
    ]
    configure_inspections(monkeypatch, configuration, client)
    value = payload()
    events = [event async for event in main.invoke(value)]
    spans = transport.get_finished_spans()
    inspections = {span.attributes["cisco.phase"]: span for span in spans if span.name == "cisco.inspect"}
    assert set(inspections) == {"input", "output"}
    assert events[-1]["ciscoStatus"] == "findings"
    assert events[-1]["splunkStatus"] == "accepted"
    assert "".join(event["text"] for event in events if event["type"] == "delta") == "A streamed answer"
    for phase, safe in (("input", False), ("output", True)):
        span = inspections[phase]
        call_index = 0 if phase == "input" else 1
        dialogue = assert_input_matches_sdk_call(span, client.inspect_conversation.call_args_list[call_index])
        expected_dialogue = value["messages"] if phase == "input" else [
            *value["messages"], {"role": "assistant", "content": "A streamed answer"},
        ]
        assert dialogue == expected_dialogue
        output = response_json(span)
        assert output["is_safe"] is safe
        assert output["action"] == ("Allow" if safe else "Block")
        assert output["severity"] == ("NONE_SEVERITY" if safe else "HIGH")
        assert output["event_id"] == f"{phase}-vendor-event"
        assert output["classifications"] == ([] if safe else ["SAFETY_VIOLATION"])
        assert "api_key" not in output
        assert "system_instructions" not in output
        assert span.attributes["app.request.id"] == value["requestId"]
        assert span.attributes["gen_ai.conversation.id"] == value["conversationId"]
        assert span.attributes["cisco.inspection.id"] == output["event_id"]
        assert format(span.context.trace_id, "032x") == events[0]["traceId"]
        assert span.end_time >= span.start_time
    assert inspections["input"].attributes["cisco.request.id"] != inspections["output"].attributes["cisco.request.id"]
    wire_payload = encode_spans(spans).SerializeToString()
    assert KEY_SENTINEL.encode() not in wire_payload
    assert SYSTEM_SENTINEL.encode() not in wire_payload
    for call in client.inspect_conversation.call_args_list:
        assert all(message.role.value in {"user", "assistant"} for message in call.kwargs["messages"])


@pytest.mark.asyncio
async def test_disabled_capture_removes_cisco_dialogue_input_and_response_output_from_final_otlp(native_export, monkeypatch):
    transport, _, configuration = native_export
    configuration.app_config.return_value = AppConfig(capture_content=False)
    client = Mock()
    client.inspect_conversation.return_value = inspection_response(
        safe=True, event_id="vendor-event", explanation="PRIVATE_RESPONSE_BODY_SENTINEL_b6b7a1",
    )
    configure_inspections(monkeypatch, configuration, client)
    value = payload()
    value["messages"][-1]["content"] = "PRIVATE_CISCO_DIALOGUE_SENTINEL_b6b7a1"
    events = [event async for event in main.invoke(value)]
    spans = transport.get_finished_spans()
    inspections = [span for span in spans if span.name == "cisco.inspect"]
    assert len(inspections) == 2
    for span in inspections:
        assert "gen_ai.input.messages" not in span.attributes
        assert "gen_ai.output.messages" not in span.attributes
        assert not span.events
        assert span.attributes["cisco.phase"] in {"input", "output"}
        assert span.attributes["app.request.id"] == value["requestId"]
        assert span.attributes["cisco.is_safe"] is True
    wire_payload = encode_spans(spans).SerializeToString()
    assert b"PRIVATE_CISCO_DIALOGUE_SENTINEL_b6b7a1" not in wire_payload
    assert b"PRIVATE_RESPONSE_BODY_SENTINEL_b6b7a1" not in wire_payload
    assert KEY_SENTINEL.encode() not in wire_payload
    assert SYSTEM_SENTINEL.encode() not in wire_payload
    assert events[-1]["ciscoStatus"] == "ok"


@pytest.mark.asyncio
async def test_vendor_failure_keeps_inspected_dialogue_input_with_sanitized_error_output(native_export, monkeypatch):
    transport, _, configuration = native_export
    client = Mock()
    client.inspect_conversation.side_effect = TimeoutError(
        f"PRIVATE_VENDOR_EXCEPTION_SENTINEL {KEY_SENTINEL} {SYSTEM_SENTINEL}",
    )
    configure_inspections(monkeypatch, configuration, client)
    events = [event async for event in main.invoke(payload())]
    spans = transport.get_finished_spans()
    inspections = [span for span in spans if span.name == "cisco.inspect"]
    assert len(inspections) == 2
    for span in inspections:
        call_index = 0 if span.attributes["cisco.phase"] == "input" else 1
        assert_input_matches_sdk_call(span, client.inspect_conversation.call_args_list[call_index])
        assert span.attributes["error.type"] == "TimeoutError"
        assert span.status.status_code == StatusCode.ERROR
        assert "gen_ai.output.messages" in span.attributes
        assert response_json(span) == {"inspection_status": "error", "error_type": "TimeoutError"}
    wire_payload = encode_spans(spans).SerializeToString()
    assert b"PRIVATE_VENDOR_EXCEPTION_SENTINEL" not in wire_payload
    assert KEY_SENTINEL.encode() not in wire_payload
    assert SYSTEM_SENTINEL.encode() not in wire_payload
    assert events[-1]["ciscoStatus"] == "error"
    assert "".join(event["text"] for event in events if event["type"] == "delta") == "A streamed answer"
