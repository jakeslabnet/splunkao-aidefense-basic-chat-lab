from types import SimpleNamespace
from unittest.mock import Mock
from uuid import uuid4

import pytest
from strands.models import Model
from opentelemetry.sdk.trace.export.in_memory_span_exporter import InMemorySpanExporter
from splunk_ao.exporter import ExportHealth
from splunk_ao.otel import SplunkAOSpanProcessor

import main
import chat_runtime.cisco as cisco_module
from chat_runtime.config import AppConfig
from chat_runtime.telemetry import Telemetry


class FakeModel(Model):
    def __init__(self, **kwargs):
        self.config = kwargs
        self.seen_messages = None

    def update_config(self, **kwargs):
        self.config.update(kwargs)

    def get_config(self):
        return self.config

    async def structured_output(self, *args, **kwargs):
        raise NotImplementedError
        yield

    async def stream(self, messages, *args, **kwargs):
        self.seen_messages = messages
        yield {"messageStart": {"role": "assistant"}}
        yield {"contentBlockStart": {"contentBlockIndex": 0, "start": {}}}
        yield {"contentBlockDelta": {"contentBlockIndex": 0, "delta": {"text": "A streamed "}}}
        yield {"contentBlockDelta": {"contentBlockIndex": 0, "delta": {"text": "answer"}}}
        yield {"contentBlockStop": {"contentBlockIndex": 0}}
        yield {"messageStop": {"stopReason": "end_turn"}}
        yield {"metadata": {"usage": {"inputTokens": 5, "outputTokens": 3, "totalTokens": 8}, "metrics": {"latencyMs": 10}}}


def payload():
    return {"requestId": str(uuid4()), "conversationId": str(uuid4()), "userId": "b" * 64,
            "messages": [{"role": "user", "content": "Hi"}, {"role": "assistant", "content": "Hello"}, {"role": "user", "content": "Continue"}]}


@pytest.mark.asyncio
async def test_runtime_uses_real_strands_hooks_streams_and_refetches_configuration(monkeypatch):
    configuration = Mock()
    configuration.app_config.side_effect = [AppConfig(), AppConfig(model_id="us.amazon.nova-lite-v1:0")]
    configuration.secret.return_value = None
    monkeypatch.setattr(main, "aws_configuration", configuration)
    models = []
    def model_factory(**kwargs):
        model = FakeModel(**kwargs)
        models.append(model)
        return model
    monkeypatch.setattr(main, "BedrockModel", model_factory)
    # Share the app's sole provider; no test exporter is attached.
    value = payload()
    first = [event async for event in main.invoke(value)]
    second = [event async for event in main.invoke(value)]
    assert [event["type"] for event in first] == ["metadata", "delta", "delta", "done"]
    assert "".join(event["text"] for event in first if event["type"] == "delta") == "A streamed answer"
    assert first[0]["modelId"] == "amazon.nova-micro-v1:0"
    assert second[0]["modelId"] == "us.amazon.nova-lite-v1:0"
    assert first[0]["traceId"] != second[0]["traceId"]
    assert len(first[0]["traceId"]) == 32
    assert models[0].config["max_tokens"] == 1024
    assert models[0] is not models[1]
    assert first[-1]["ciscoStatus"] == first[-1]["splunkStatus"] == "unconfigured"
    assert configuration.app_config.call_count == 2


@pytest.mark.asyncio
async def test_invalid_request_does_not_read_aws_or_call_a_model(monkeypatch):
    configuration = Mock()
    model = Mock()
    monkeypatch.setattr(main, "aws_configuration", configuration)
    monkeypatch.setattr(main, "BedrockModel", model)
    events = [event async for event in main.invoke({"messages": []})]
    assert events[0]["code"] == "INVALID_REQUEST"
    configuration.app_config.assert_not_called()
    model.assert_not_called()


@pytest.mark.asyncio
async def test_config_failure_does_not_expose_exception_or_invoke_model(monkeypatch):
    configuration = Mock()
    configuration.app_config.side_effect = RuntimeError("secret-bearing exception")
    model = Mock()
    monkeypatch.setattr(main, "aws_configuration", configuration)
    monkeypatch.setattr(main, "BedrockModel", model)
    events = [event async for event in main.invoke(payload())]
    assert events[0]["code"] == "CONFIGURATION_ERROR"
    assert "secret-bearing" not in str(events)
    model.assert_not_called()


@pytest.mark.asyncio
async def test_runtime_monitor_timeout_keeps_streamed_reply_available(monkeypatch):
    configuration = Mock()
    configuration.app_config.return_value = AppConfig()
    configuration.secret.side_effect = lambda name: {"api_key": "unit-test-placeholder", "inspection_origin": "https://us.api.inspect.aidefense.security.cisco.com"} if name == "CISCO_SECRET_ARN" else None
    client = Mock()
    client.inspect_conversation.side_effect = TimeoutError("secret-bearing failure")
    monkeypatch.setattr(main, "aws_configuration", configuration)
    monkeypatch.setattr(cisco_module, "make_client", lambda secret: client)
    monkeypatch.setattr(main, "BedrockModel", lambda **kwargs: FakeModel(**kwargs))
    events = [event async for event in main.invoke(payload())]
    assert "".join(event["text"] for event in events if event["type"] == "delta") == "A streamed answer"
    assert events[-1]["ciscoStatus"] == "error"
    assert client.inspect_conversation.call_count == 2
    assert not any(event["type"] == "error" for event in events)


@pytest.mark.asyncio
async def test_native_strands_and_splunk_trace_contains_content_usage_and_cisco_correlation(monkeypatch):
    class AckingMemoryExporter(InMemorySpanExporter):
        @property
        def export_health(self):
            return ExportHealth(healthy=True, consecutive_failures=0, last_failure=None)
    exported = AckingMemoryExporter()
    factory = lambda secret, config: SplunkAOSpanProcessor(_exporter=exported)
    monkeypatch.setattr(main.telemetry, "_processor_factory", factory)
    configuration = Mock()
    configuration.app_config.return_value = AppConfig()
    configuration.secret.side_effect = lambda name: ({"api_key": "unit-test-placeholder", "inspection_origin": "https://us.api.inspect.aidefense.security.cisco.com"} if name == "CISCO_SECRET_ARN" else {"realm": "us1", "o11y_token": "unit-test-placeholder"})
    client = Mock()
    client.inspect_conversation.return_value = SimpleNamespace(is_safe=True, classifications=[], event_id="cisco-event-id")
    monkeypatch.setattr(main, "aws_configuration", configuration)
    monkeypatch.setattr(cisco_module, "make_client", lambda secret: client)
    monkeypatch.setattr(main, "BedrockModel", lambda **kwargs: FakeModel(**kwargs))
    value = payload()
    events = [event async for event in main.invoke(value)]
    spans = exported.get_finished_spans()
    assert events[-1]["splunkStatus"] == "accepted"
    assert events[-1]["ciscoStatus"] == "ok"
    assert len([span for span in spans if span.name == "cisco.inspect"]) == 2
    assert {format(span.context.trace_id, "032x") for span in spans} == {events[0]["traceId"]}
    root = next(span for span in spans if span.name == "chat.turn")
    assert root.attributes["gen_ai.conversation.id"] == value["conversationId"]
    assert root.attributes["app.request.id"] == value["requestId"]
    model_span = next(span for span in spans if (span.attributes or {}).get("gen_ai.usage.output_tokens") == 3)
    recorded = str(model_span.attributes) + str([dict(event.attributes) for event in model_span.events])
    assert "A streamed answer" in recorded
    assert "Continue" in recorded
