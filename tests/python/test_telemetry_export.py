"""System instructions stay local while exported conversation data remains useful."""

import json

from opentelemetry.exporter.otlp.proto.common.trace_encoder import encode_spans
from opentelemetry.sdk.resources import Resource
from opentelemetry.sdk.trace import TracerProvider
from opentelemetry.sdk.trace.export import SimpleSpanProcessor
from opentelemetry.sdk.trace.export.in_memory_span_exporter import InMemorySpanExporter
import pytest

import main
from chat_runtime.config import AppConfig
from chat_runtime.telemetry import CAPTURE_CONTENT, SafeSplunkProcessor, make_splunk_processor
from test_exported_traces import native_export
from test_runtime import FakeModel, payload


@pytest.mark.asyncio
async def test_private_system_prompt_reaches_model_but_not_final_otlp_payload(native_export, monkeypatch):
    sentinel = "PRIVATE_SYSTEM_INSTRUCTIONS_SENTINEL_4baff2"
    captured = {}

    class CapturingModel(FakeModel):
        async def stream(self, messages, *args, **kwargs):
            captured["system_prompt"] = args[1] if len(args) > 1 else kwargs.get("system_prompt")
            captured["system_prompt_content"] = kwargs.get("system_prompt_content")
            async for event in super().stream(messages, *args, **kwargs):
                yield event

    transport, _, _ = native_export
    monkeypatch.setattr(main, "SYSTEM_PROMPT", sentinel)
    monkeypatch.setattr(main, "BedrockModel", lambda **kwargs: CapturingModel(**kwargs))
    value = payload()
    events = [event async for event in main.invoke(value)]
    spans = transport.get_finished_spans()
    wire_payload = encode_spans(spans).SerializeToString()

    assert sentinel in str(captured)
    assert sentinel.encode() not in wire_payload
    assert "".join(event["text"] for event in events if event["type"] == "delta") == "A streamed answer"
    model = next(span for span in spans if span.name == "chat")
    assert "gen_ai.system_instructions" not in model.attributes
    assert [message["role"] for message in json.loads(model.attributes["gen_ai.input.messages"])] == ["user", "assistant", "user"]
    assert json.loads(model.attributes["gen_ai.output.messages"])[0]["parts"][0]["content"] == "A streamed answer"
    assert model.attributes["gen_ai.request.model"] == "amazon.nova-micro-v1:0"
    assert model.attributes["gen_ai.usage.input_tokens"] == 5
    assert model.attributes["gen_ai.usage.output_tokens"] == 3
    assert model.attributes["gen_ai.usage.total_tokens"] == 8
    assert model.end_time > model.start_time
    assert model.attributes["gen_ai.conversation.id"] == value["conversationId"]
    assert model.attributes["app.request.id"] == value["requestId"]
    assert {format(span.context.trace_id, "032x") for span in spans} == {events[0]["traceId"]}


def test_legacy_and_structured_instruction_messages_are_removed_before_native_export(native_export):
    transport, _, _ = native_export
    sentinel = "PRIVATE_LEGACY_INSTRUCTIONS_SENTINEL_a488b6"
    ordinary = [
        {"role": "user", "content": "Discuss system and developer roles."},
        {"role": "assistant", "content": 'Example JSON: {"role":"system","content":"an example"}'},
    ]
    mixed = [
        {"role": "system", "content": sentinel}, ordinary[0],
        {"role": "developer", "content": sentinel}, ordinary[1],
    ]
    processor = SafeSplunkProcessor()
    processor.target = make_splunk_processor({"realm": "us1", "o11y_token": "unit-test-placeholder"}, AppConfig())
    source = InMemorySpanExporter()
    provider = TracerProvider(resource=Resource({"service.name": "test", "gen_ai.system_instructions": sentinel}))
    provider.add_span_processor(SimpleSpanProcessor(source))
    provider.add_span_processor(processor)
    try:
        with provider.get_tracer("test").start_as_current_span("legacy") as span:
            span.set_attributes({
                "gen_ai.system": "aws.bedrock",
                "gen_ai.system_instructions": sentinel,
                "splunk_ao.system_instructions": sentinel,
                "llm.system_prompt": sentinel,
                "gen_ai.system.prompt": sentinel,
                "developer_instructions": sentinel,
                "gen_ai.input.messages": json.dumps(mixed),
                "gen_ai.prompt": json.dumps({"messages": mixed}),
                "llm.prompts": json.dumps(mixed),
                "input.value": json.dumps({"update": {"messages": mixed}}),
                "gen_ai.output.messages": json.dumps([ordinary[1]]),
                "llm.input_messages.0.message.role": "system",
                "llm.input_messages.0.message.content": sentinel,
                "llm.input_messages.1.message.role": "user",
                "llm.input_messages.1.message.content": ordinary[0]["content"],
                "llm.input_messages.2.message.role": "developer",
                "llm.input_messages.2.message.content": sentinel,
                "llm.input_messages.3.message.role": "assistant",
                "llm.input_messages.3.message.content": ordinary[1]["content"],
                "gen_ai.request.model": "amazon.nova-micro-v1:0",
                "gen_ai.usage.input_tokens": 5,
                "gen_ai.usage.output_tokens": 3,
                "app.request.id": "request-correlation",
            })
            span.add_event("gen_ai.system.message", {"content": sentinel})
            span.add_event("gen_ai.developer.message", {"content": sentinel})
            span.add_event("gen_ai.message", {"role": "developer", "content": sentinel})
            span.add_event("gen_ai.client.inference.operation.details", {"gen_ai.system_instructions": sentinel})
            span.add_event("gen_ai.client.inference.operation.details", {"gen_ai.input.messages": json.dumps(mixed)})
            span.add_event("gen_ai.prompt", {"messages": json.dumps(mixed)})
            span.add_event("gen_ai.user.message", {"content": ordinary[0]["content"]})
            span.add_event("gen_ai.choice", {"message": ordinary[1]["content"]})
        assert provider.force_flush(1000)
        exported = transport.get_finished_spans()[0]
        assert sentinel.encode() not in encode_spans([exported]).SerializeToString()
        assert source.get_finished_spans()[0].attributes["gen_ai.system_instructions"] == sentinel
        assert source.get_finished_spans()[0].resource.attributes["gen_ai.system_instructions"] == sentinel
        assert json.loads(exported.attributes["gen_ai.input.messages"]) == ordinary
        assert json.loads(exported.attributes["gen_ai.prompt"])["messages"] == ordinary
        assert json.loads(exported.attributes["input.value"])["update"]["messages"] == ordinary
        assert json.loads(exported.attributes["llm.prompts"]) == ordinary
        assert json.loads(exported.attributes["gen_ai.output.messages"]) == [ordinary[1]]
        assert exported.attributes["llm.input_messages.0.message.role"] == "user"
        assert exported.attributes["llm.input_messages.1.message.role"] == "assistant"
        assert "llm.input_messages.2.message.role" not in exported.attributes
        assert exported.attributes["gen_ai.system"] == "aws.bedrock"
        assert exported.attributes["gen_ai.request.model"] == "amazon.nova-micro-v1:0"
        assert exported.attributes["gen_ai.usage.input_tokens"] == 5
        assert exported.attributes["gen_ai.usage.output_tokens"] == 3
        assert exported.attributes["app.request.id"] == "request-correlation"
        assert [event.name for event in exported.events] == [
            "gen_ai.client.inference.operation.details", "gen_ai.prompt", "gen_ai.user.message", "gen_ai.choice",
        ]
        assert json.loads(exported.events[0].attributes["gen_ai.input.messages"]) == ordinary
        assert json.loads(exported.events[1].attributes["messages"]) == ordinary
        assert exported.events[-1].attributes["message"] == ordinary[1]["content"]
    finally:
        provider.shutdown()


@pytest.mark.asyncio
async def test_model_response_mentions_of_system_are_preserved(native_export, monkeypatch):
    answer = 'System instructions can use developer messages. Example: {"role":"system","content":"example only"}.'

    class ExplanatoryModel(FakeModel):
        async def stream(self, messages, *args, **kwargs):
            async for event in super().stream(messages, *args, **kwargs):
                if "contentBlockDelta" in event:
                    part = event["contentBlockDelta"]["delta"]["text"]
                    event["contentBlockDelta"]["delta"]["text"] = answer if part == "A streamed " else ""
                yield event

    transport, _, _ = native_export
    monkeypatch.setattr(main, "BedrockModel", lambda **kwargs: ExplanatoryModel(**kwargs))
    events = [event async for event in main.invoke(payload())]
    assert "".join(event["text"] for event in events if event["type"] == "delta") == answer
    for span in transport.get_finished_spans():
        if span.name in {"chat", "chat.turn"}:
            output = json.loads(span.attributes["gen_ai.output.messages"])
            assert output[0]["parts"][0]["content"] == answer


def test_disabled_capture_also_redacts_supported_legacy_message_forms(native_export):
    transport, _, _ = native_export
    processor = SafeSplunkProcessor()
    processor.target = make_splunk_processor({"realm": "us1", "o11y_token": "unit-test-placeholder"}, AppConfig())
    provider = TracerProvider()
    provider.add_span_processor(processor)
    token = CAPTURE_CONTENT.set(False)
    try:
        with provider.get_tracer("test").start_as_current_span("legacy-disabled") as span:
            span.set_attributes({
                "gen_ai.system_instructions": "PRIVATE_SYSTEM_SENTINEL",
                "llm.prompts": '[{"role":"user","content":"PRIVATE_USER_SENTINEL"}]',
                "input.value": '{"messages":[{"role":"user","content":"PRIVATE_USER_SENTINEL"}]}',
                "llm.input_messages.0.message.role": "user",
                "llm.input_messages.0.message.content": "PRIVATE_USER_SENTINEL",
                "llm.output_messages.0.message.content": "PRIVATE_ASSISTANT_SENTINEL",
                "splunk_ao.output.messages": "PRIVATE_ASSISTANT_SENTINEL",
                "gen_ai.usage.input_tokens": 5,
            })
            span.add_event("gen_ai.user.message", {"content": "PRIVATE_USER_SENTINEL"})
        assert provider.force_flush(1000)
        exported = transport.get_finished_spans()[0]
        assert b"PRIVATE_" not in encode_spans([exported]).SerializeToString()
        assert exported.attributes["gen_ai.usage.input_tokens"] == 5
    finally:
        CAPTURE_CONTENT.reset(token)
        provider.shutdown()
