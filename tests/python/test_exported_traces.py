"""Exercise Strands through the real Splunk exporter transform without HTTP."""

import json
from unittest.mock import Mock

from opentelemetry.sdk.trace.export.in_memory_span_exporter import InMemorySpanExporter
import pytest
from splunk_ao import LlmSpan, WorkflowSpan
from splunk_ao.converter import build_span_attributes
from splunk_ao.exporter import ExportHealth

import main
from chat_runtime.config import AppConfig
import chat_runtime.telemetry as telemetry_module
from test_runtime import FakeModel, payload


class AcknowledgingMemoryTransport(InMemorySpanExporter):
    @property
    def export_health(self):
        return ExportHealth(healthy=True, consecutive_failures=0, last_failure=None)


@pytest.fixture
def native_export(monkeypatch):
    """Replace only the final network transport, retaining the SDK transformation."""
    transport = AcknowledgingMemoryTransport()
    transport_settings = {}
    native_builder = telemetry_module.build_o11y_exporter

    def transport_factory(**settings):
        transport_settings.update(settings)
        return transport

    def builder(*args, **kwargs):
        return native_builder(*args, _exporter_factory=transport_factory, **kwargs)

    main.telemetry.configure(None, AppConfig(), "unit-test-reset")
    monkeypatch.setattr(telemetry_module, "build_o11y_exporter", builder)
    monkeypatch.setattr(main.telemetry, "_processor_factory", telemetry_module.make_splunk_processor)
    configuration = Mock()
    configuration.app_config.return_value = AppConfig()
    configuration.secret.side_effect = lambda name: (
        None if name == "CISCO_SECRET_ARN"
        else {"realm": "us1", "o11y_token": "unit-test-placeholder"}
    )
    monkeypatch.setattr(main, "aws_configuration", configuration)
    monkeypatch.setattr(main, "BedrockModel", lambda **kwargs: FakeModel(**kwargs))
    yield transport, transport_settings, configuration
    main.telemetry.configure(None, AppConfig(), "unit-test-cleanup")


@pytest.mark.asyncio
async def test_final_sdk_export_contains_native_model_messages_usage_and_workflow_summary(native_export):
    transport, settings, _ = native_export
    value = payload()
    events = [event async for event in main.invoke(value)]
    spans = transport.get_finished_spans()
    model_span = next(span for span in spans if span.name == "chat")
    root_span = next(span for span in spans if span.name == "chat.turn")
    streamed = "".join(event["text"] for event in events if event["type"] == "delta")

    # Compare post-exporter attributes with the SDK's own native span schema,
    # rather than accepting content that exists only in pre-export span events.
    expected_model = build_span_attributes(LlmSpan(
        input=value["messages"], output={"role": "assistant", "content": streamed},
        model="amazon.nova-micro-v1:0", finish_reason="end_turn",
        metrics={"num_input_tokens": 5, "num_output_tokens": 3, "num_total_tokens": 8},
    ))
    expected_workflow = build_span_attributes(WorkflowSpan(
        name="chat.turn", input=value["messages"], output=streamed,
    ))
    attrs = model_span.attributes
    assert json.loads(attrs["gen_ai.input.messages"]) == json.loads(expected_model["gen_ai.input.messages"])
    assert json.loads(attrs["gen_ai.output.messages"]) == json.loads(expected_model["gen_ai.output.messages"])
    assert "gen_ai.system_instructions" not in attrs
    for key in ("gen_ai.usage.input_tokens", "gen_ai.usage.output_tokens", "gen_ai.request.model"):
        assert attrs[key] == expected_model[key]
    assert attrs["gen_ai.usage.total_tokens"] == 8
    assert attrs["splunk_ao.system"] == "splunk_ao_python"
    assert not model_span.events

    root = root_span.attributes
    assert root["gen_ai.operation.name"] == expected_workflow["gen_ai.operation.name"] == "invoke_workflow"
    assert root["gen_ai.workflow.name"] == "chat.turn"
    assert json.loads(root["gen_ai.input.messages"]) == json.loads(expected_workflow["gen_ai.input.messages"])
    assert json.loads(root["gen_ai.output.messages"])[0]["parts"] == json.loads(expected_workflow["gen_ai.output.messages"])[0]["parts"]
    assert root["app.response.complete"] is True
    assert root["gen_ai.conversation.id"] == value["conversationId"]
    assert root["app.request.id"] == value["requestId"]
    assert "gen_ai.usage.input_tokens" not in root
    assert "gen_ai.usage.output_tokens" not in root
    assert "gen_ai.request.model" not in root
    assert root_span.resource.attributes["splunk_ao.project.name"] == "agentcore-chat-lab"
    assert root_span.resource.attributes["splunk_ao.logstream.name"] == "chat"
    assert settings["endpoint"] == "https://ingest.us1.observability.splunkcloud.com/v2/trace/otlp"
    assert settings["headers"]["project"] == "agentcore-chat-lab"
    assert settings["headers"]["logstream"] == "chat"
    assert events[-1]["splunkStatus"] == "accepted"


@pytest.mark.asyncio
async def test_final_export_removes_model_and_root_content_when_capture_disabled(native_export):
    transport, _, configuration = native_export
    configuration.app_config.return_value = AppConfig(capture_content=False)
    events = [event async for event in main.invoke(payload())]
    spans = transport.get_finished_spans()
    for span in spans:
        assert not span.events
        for key in ("gen_ai.input.messages", "gen_ai.output.messages", "gen_ai.system_instructions"):
            assert key not in span.attributes
        assert "Continue" not in str(span.attributes)
        assert "A streamed answer" not in str(span.attributes)
        assert main.SYSTEM_PROMPT not in str(span.attributes)
    model_span = next(span for span in spans if span.name == "chat")
    assert model_span.attributes["gen_ai.usage.input_tokens"] == 5
    assert model_span.attributes["gen_ai.usage.output_tokens"] == 3
    assert events[-1]["splunkStatus"] == "accepted"


@pytest.mark.asyncio
async def test_incomplete_stream_never_reports_a_completed_workflow_reply(native_export, monkeypatch):
    class InterruptedModel(FakeModel):
        async def stream(self, messages, *args, **kwargs):
            yield {"messageStart": {"role": "assistant"}}
            yield {"contentBlockStart": {"contentBlockIndex": 0, "start": {}}}
            yield {"contentBlockDelta": {"contentBlockIndex": 0, "delta": {"text": "Partial reply"}}}
            raise RuntimeError("The model disconnected")

    transport, _, _ = native_export
    monkeypatch.setattr(main, "BedrockModel", lambda **kwargs: InterruptedModel(**kwargs))
    events = [event async for event in main.invoke(payload())]
    root = next(span for span in transport.get_finished_spans() if span.name == "chat.turn")
    assert any(event.get("text") == "Partial reply" for event in events)
    assert any(event.get("code") == "MODEL_ERROR" for event in events)
    assert root.attributes["app.response.complete"] is False
    assert "gen_ai.output.messages" not in root.attributes
