import json
import logging
from types import SimpleNamespace
from unittest.mock import Mock
from uuid import uuid4

from aidefense.runtime.models import Action, Classification, DetectedPII, InspectResponse, RuleName, RuleResult, Severity
from opentelemetry.sdk.trace import TracerProvider
from opentelemetry.sdk.trace.export import SimpleSpanProcessor
from opentelemetry.sdk.trace.export.in_memory_span_exporter import InMemorySpanExporter
import pytest
from strands.hooks import AfterModelCallEvent, BeforeModelCallEvent, HookRegistry

from chat_runtime.cisco import MAX_INSPECTION_OUTPUT_BYTES, CiscoMonitor, make_client
from chat_runtime.config import AppConfig
from chat_runtime.diagnostics import diagnostic, safe_error_code
from chat_runtime.telemetry import CAPTURE_CONTENT, OsEntropyIdGenerator, SafeSplunkProcessor, Telemetry, make_splunk_processor
from chat_runtime.validation import ChatRequest


SECRET = {"api_key": "unit-test-placeholder".ljust(64, "0"), "inspection_origin": "https://us.api.inspect.aidefense.security.cisco.com"}


def request():
    return ChatRequest(str(uuid4()), str(uuid4()), "a" * 64, [{"role": "user", "content": "A question"}])


def tracer():
    provider = TracerProvider(id_generator=OsEntropyIdGenerator())
    exporter = InMemorySpanExporter()
    provider.add_span_processor(SimpleSpanProcessor(exporter))
    return provider.get_tracer("unit-test"), exporter


@pytest.mark.asyncio
async def test_findings_preserve_the_model_request_and_reply():
    t, exported = tracer()
    client = Mock()
    client.inspect_conversation.return_value = SimpleNamespace(is_safe=False, classifications=["SAFETY_VIOLATION"], event_id="event-123")
    monitor = CiscoMonitor(request(), SECRET, t, client_factory=lambda secret: client)
    agent = SimpleNamespace(messages=[{"role": "user", "content": [{"text": "A question"}]}])
    before = BeforeModelCallEvent(agent=agent)
    after = AfterModelCallEvent(agent=agent, stop_response=AfterModelCallEvent.ModelStopResponse(message={"role": "assistant", "content": [{"text": "The unchanged answer"}]}, stop_reason="end_turn"))
    registry = HookRegistry()
    monitor.register_hooks(registry)
    await registry.invoke_callbacks_async(before)
    await registry.invoke_callbacks_async(after)
    assert before.cancel is False
    assert after.retry is False
    assert after.stop_response.message["content"][0]["text"] == "The unchanged answer"
    assert monitor.status == "findings"
    assert len(exported.get_finished_spans()) == 2
    output_call = client.inspect_conversation.call_args
    assert output_call.kwargs["messages"][-1].content == "The unchanged answer"
    assert output_call.kwargs["metadata"].client_transaction_id == monitor.request.request_id


@pytest.mark.asyncio
async def test_inspection_timeout_fails_open_and_redacts_exception(caplog):
    t, _ = tracer()
    client = Mock()
    client.inspect_conversation.side_effect = TimeoutError("Bearer secret-should-not-be-logged full prompt")
    monitor = CiscoMonitor(request(), SECRET, t, client_factory=lambda secret: client)
    before = BeforeModelCallEvent(agent=SimpleNamespace(messages=[{"role": "user", "content": [{"text": "Question"}]}]))
    with caplog.at_level(logging.INFO, logger="agentcore_chat"):
        await monitor.before_model(before)
    assert before.cancel is False
    assert monitor.status == "error"
    assert "TimeoutError" in caplog.text
    assert "secret-should-not-be-logged" not in caplog.text
    assert "full prompt" not in caplog.text


def test_cisco_client_configuration_accepts_rotated_origin_without_singleton_staleness():
    first = make_client(SECRET)
    second = make_client({**SECRET, "inspection_origin": "https://eu.api.inspect.aidefense.security.cisco.com"})
    assert first.endpoint.startswith("https://us.")
    assert second.endpoint.startswith("https://eu.")
    assert first.config is not second.config


def test_ids_use_fresh_os_entropy():
    generator = OsEntropyIdGenerator()
    traces = {generator.generate_trace_id() for _ in range(1000)}
    spans = {generator.generate_span_id() for _ in range(1000)}
    assert len(traces) == len(spans) == 1000
    assert min(traces) > 0 and max(traces) < 2 ** 128
    assert min(spans) > 0 and max(spans) < 2 ** 64


def test_splunk_sdk_builds_without_environment_or_control_plane_network(monkeypatch):
    monkeypatch.delenv("SPLUNK_AO_O11Y_TOKEN", raising=False)
    processor = make_splunk_processor({"realm": "us1", "o11y_token": "unit-test-placeholder"}, AppConfig())
    assert processor.exporter is not None
    assert processor.force_flush(100)
    processor.shutdown()
    import os
    assert "SPLUNK_AO_O11Y_TOKEN" not in os.environ


def test_splunk_export_failure_is_reported_without_raising_or_secret_logs(caplog):
    processor = Mock()
    processor.force_flush.return_value = False
    processor.export_health = SimpleNamespace(healthy=None)
    manager = Telemetry(processor_factory=lambda secret, config: processor)
    assert manager.configure({"realm": "us1", "o11y_token": "unit-test-placeholder"}, AppConfig(), "request") == "unconfirmed"
    with caplog.at_level(logging.INFO, logger="agentcore_chat"):
        assert manager.flush("request") == "error"
    assert "TelemetryExportUnconfirmed" in caplog.text
    assert "unit-test-placeholder" not in caplog.text


def test_splunk_acknowledgement_and_credential_rotation():
    first, second = Mock(), Mock()
    for processor in (first, second):
        processor.force_flush.return_value = True
        processor.export_health = SimpleNamespace(healthy=True)
    factory = Mock(side_effect=[first, second])
    manager = Telemetry(processor_factory=factory)
    original = {"realm": "us1", "o11y_token": "unit-test-placeholder"}
    manager.configure(original, AppConfig(), "request")
    assert manager.flush("request") == "accepted"
    manager.configure(original, AppConfig(), "request")
    assert factory.call_count == 1
    manager.configure({**original, "o11y_token": "unit-test-rotated"}, AppConfig(), "request")
    assert factory.call_count == 2
    first.shutdown.assert_called_once()
    manager.configure(None, AppConfig(), "request")
    assert manager.flush("request") == "unconfigured"
    second.shutdown.assert_called_once()


def test_disabled_content_capture_removes_genai_content_before_export():
    provider = TracerProvider()
    router = SafeSplunkProcessor()
    target = Mock()
    router.target = target
    provider.add_span_processor(router)
    token = CAPTURE_CONTENT.set(False)
    try:
        with provider.get_tracer("test").start_as_current_span("chat") as span:
            span.set_attribute("gen_ai.input.messages", "sensitive conversation")
            span.set_attribute("gen_ai.usage.input_tokens", 12)
            span.add_event("gen_ai.user.message", {"content": "sensitive conversation"})
    finally:
        CAPTURE_CONTENT.reset(token)
    exported = target.on_end.call_args.args[0]
    assert "gen_ai.input.messages" not in exported.attributes
    assert exported.attributes["gen_ai.usage.input_tokens"] == 12
    assert exported.events == ()


def test_diagnostic_allowlist_drops_arbitrary_secret_and_newline_fields(caplog):
    with caplog.at_level(logging.INFO, logger="agentcore_chat"):
        diagnostic("integration_error", "request-id", integration="cisco\nforged", secret="hidden", message="private prompt", errorCode="TimeoutError")
    assert "hidden" not in caplog.text
    assert "private prompt" not in caplog.text
    assert "cisco_forged" in caplog.text
    assert safe_error_code(ValueError("sensitive message")) == "ValueError"


@pytest.mark.asyncio
@pytest.mark.parametrize("system", [
    "PRIVATE_SYSTEM_SENTINEL",
    [{"text": "PRIVATE_SYSTEM_SENTINEL"}, {"cachePoint": {"type": "default"}}],
])
async def test_system_prompt_is_excluded_with_immutable_dialogue_and_one_completion(system):
    t, exported = tracer()
    client = Mock()
    client.inspect_conversation.return_value = SimpleNamespace(is_safe=True, classifications=[], event_id="event-123")
    monitor = CiscoMonitor(request(), SECRET, t, client_factory=lambda secret: client)
    history = [
        {"role": "system", "content": "PRIVATE_SYSTEM_SENTINEL"},
        {"role": "developer", "content": "PRIVATE_DEVELOPER_SENTINEL"},
        {"role": "user", "content": [{"text": "Original question"}]},
        {"role": "assistant", "content": [{"text": "Earlier answer"}]},
        {"role": "user", "content": [{"text": "Follow-up question"}]},
    ]
    agent = SimpleNamespace(messages=history, system_prompt=system)
    if isinstance(system, list):
        agent.system_prompt_content = system
    before = BeforeModelCallEvent(agent=agent)
    await monitor.before_model(before)
    # Mutating model history after input inspection cannot change output context.
    history[2]["content"][0]["text"] = "Later mutation"
    response = {"role": "assistant", "content": [{"text": "One completion"}]}
    after = AfterModelCallEvent(agent=agent, stop_response=AfterModelCallEvent.ModelStopResponse(message=response, stop_reason="end_turn"))
    await monitor.after_model(after)
    calls = client.inspect_conversation.call_args_list
    input_messages = [(message.role.value, message.content) for message in calls[0].kwargs["messages"]]
    output_messages = [(message.role.value, message.content) for message in calls[1].kwargs["messages"]]
    assert input_messages == [
        ("user", "Original question"), ("assistant", "Earlier answer"), ("user", "Follow-up question"),
    ]
    assert output_messages == [*input_messages, ("assistant", "One completion")]
    for span, expected in zip(exported.get_finished_spans(), (input_messages, output_messages)):
        captured = json.loads(span.attributes["gen_ai.input.messages"])
        assert [(item["role"], item["parts"][0]["content"]) for item in captured] == expected
    assert all("PRIVATE_SYSTEM_SENTINEL" not in message.content and "PRIVATE_DEVELOPER_SENTINEL" not in message.content
               for call in calls for message in call.kwargs["messages"])
    assert agent.system_prompt == system
    assert history[0]["content"] == "PRIVATE_SYSTEM_SENTINEL"
    assert history[1]["content"] == "PRIVATE_DEVELOPER_SENTINEL"
    assert before.cancel is False and after.retry is False


def test_cisco_sdk_boundary_excludes_instruction_roles_and_preserves_dialogue():
    t, _ = tracer()
    client = Mock()
    client.inspect_conversation.return_value = SimpleNamespace(is_safe=True, classifications=[], event_id="event-123")
    monitor = CiscoMonitor(request(), SECRET, t, client_factory=lambda secret: client)
    monitor.inspect("output", [
        {"role": "system", "content": "PRIVATE_SYSTEM_SENTINEL"},
        {"role": "developer", "content": "PRIVATE_DEVELOPER_SENTINEL"},
        {"role": "user", "content": "Question"},
        {"role": "assistant", "content": "Answer"},
    ])
    messages = client.inspect_conversation.call_args.kwargs["messages"]
    assert [(message.role.value, message.content) for message in messages] == [
        ("user", "Question"), ("assistant", "Answer"),
    ]


def inspection_response():
    return InspectResponse(
        is_safe=False, action=Action.ALLOW, severity=Severity.HIGH,
        classifications=[Classification.SECURITY_VIOLATION],
        rules=[RuleResult(rule_name=RuleName.PROMPT_INJECTION, entity_types=["Email Address"],
                          rule_id=7, classification=Classification.SECURITY_VIOLATION, profile_id="profile-1")],
        processed_rules=[RuleResult(rule_name=RuleName.PII, rule_id=8)],
        attack_technique="Synthetic technique", explanation="Synthetic inspection finding",
        client_transaction_id="transaction-1", event_id="inspection-event-1",
        detected_pii=[DetectedPII(message_index="0", type="Email Address", start_index="2", end_index="10")],
    )


def cisco_output(span):
    messages = json.loads(span.attributes["gen_ai.output.messages"])
    assert len(messages) == 1 and messages[0]["role"] == "assistant"
    assert messages[0]["parts"][0]["type"] == "text"
    return json.loads(messages[0]["parts"][0]["content"])


@pytest.mark.parametrize("phase", ["input", "output"])
def test_cisco_inspection_workflow_output_contains_only_sdk_response_fields(phase):
    t, exported = tracer()
    result = inspection_response()
    # Unknown attributes and secret-looking fields are never serialized.
    result.api_key = "UNKNOWN_KEY_SENTINEL"
    result.system_instructions = "PRIVATE_SYSTEM_SENTINEL"
    result.rules[0].raw_body = "UNKNOWN_RULE_SENTINEL"
    result.explanation += " " + SECRET["api_key"]
    client = Mock()
    client.inspect_conversation.return_value = result
    monitor = CiscoMonitor(request(), SECRET, t, client_factory=lambda secret: client)
    monitor.inspect(phase, [{"role": "user", "content": "PRIVATE_PROMPT_SENTINEL"}])
    span = exported.get_finished_spans()[0]
    assert span.attributes["gen_ai.operation.name"] == "invoke_workflow"
    assert span.attributes["gen_ai.workflow.name"] == "cisco.inspect"
    assert span.attributes["cisco.phase"] == phase
    assert span.attributes["cisco.inspection.id"] == "inspection-event-1"
    output = cisco_output(span)
    assert output == {
        "is_safe": False, "action": "Allow", "severity": "HIGH",
        "classifications": ["SECURITY_VIOLATION"], "attack_technique": "Synthetic technique",
        "explanation": "Synthetic inspection finding [REDACTED]",
        "client_transaction_id": "transaction-1", "event_id": "inspection-event-1",
        "rules": [{"rule_name": "Prompt Injection", "entity_types": ["Email Address"], "rule_id": 7,
                   "classification": "SECURITY_VIOLATION", "profile_id": "profile-1"}],
        "processed_rules": [{"rule_name": "PII", "rule_id": 8}],
        "detected_pii": [{"message_index": "0", "type": "Email Address", "start_index": "2", "end_index": "10"}],
    }
    serialized = span.attributes["gen_ai.output.messages"]
    assert all(value not in serialized for value in (
        SECRET["api_key"], "UNKNOWN_KEY_SENTINEL", "PRIVATE_SYSTEM_SENTINEL", "UNKNOWN_RULE_SENTINEL", "PRIVATE_PROMPT_SENTINEL",
    ))
    assert json.loads(span.attributes["gen_ai.input.messages"]) == [
        {"role": "user", "parts": [{"type": "text", "content": "PRIVATE_PROMPT_SENTINEL"}]},
    ]
    assert monitor.status == "findings"


def test_cisco_inspection_output_is_bounded_valid_json_and_deterministic():
    t, exported = tracer()
    result = inspection_response()
    result.explanation = '雪"\\\n' * 10000
    result.rules *= 200
    result.processed_rules = [RuleResult(rule_name=RuleName.PII, entity_types=["Entity" * 500] * 100)] * 100
    client = Mock()
    client.inspect_conversation.return_value = result
    monitor = CiscoMonitor(request(), SECRET, t, client_factory=lambda secret: client)
    for _ in range(2):
        monitor.inspect("output", [{"role": "user", "content": "Question"}])
    first, second = exported.get_finished_spans()
    output = cisco_output(first)
    assert output["truncated"] is True
    assert output["is_safe"] is False and output["event_id"] == "inspection-event-1"
    assert len(first.attributes["gen_ai.output.messages"].encode("utf-8")) <= MAX_INSPECTION_OUTPUT_BYTES
    assert first.attributes["gen_ai.output.messages"] == second.attributes["gen_ai.output.messages"]
    assert monitor.status == "findings"


def test_cisco_inspection_output_respects_disabled_content_capture():
    t, exported = tracer()
    client = Mock()
    client.inspect_conversation.return_value = inspection_response()
    monitor = CiscoMonitor(request(), SECRET, t, client_factory=lambda secret: client)
    token = CAPTURE_CONTENT.set(False)
    try:
        monitor.inspect("input", [{"role": "user", "content": "Question"}])
    finally:
        CAPTURE_CONTENT.reset(token)
    span = exported.get_finished_spans()[0]
    assert "gen_ai.output.messages" not in span.attributes
    assert "gen_ai.input.messages" not in span.attributes
    assert span.attributes["cisco.is_safe"] is False
    assert monitor.status == "findings"


def test_cisco_inspection_failure_output_omits_exception_text():
    t, exported = tracer()
    client = Mock()
    client.inspect_conversation.side_effect = TimeoutError("Bearer CREDENTIAL_SENTINEL PRIVATE_SYSTEM_SENTINEL")
    monitor = CiscoMonitor(request(), SECRET, t, client_factory=lambda secret: client)
    monitor.inspect("input", [{"role": "user", "content": "Question"}])
    span = exported.get_finished_spans()[0]
    assert cisco_output(span) == {"inspection_status": "error", "error_type": "TimeoutError"}
    assert json.loads(span.attributes["gen_ai.input.messages"])[0]["parts"][0]["content"] == "Question"
    assert "CREDENTIAL_SENTINEL" not in span.attributes["gen_ai.output.messages"]
    assert "PRIVATE_SYSTEM_SENTINEL" not in span.attributes["gen_ai.output.messages"]
    assert monitor.status == "error"


def test_cisco_inspection_output_formatting_failure_preserves_findings(monkeypatch, caplog):
    t, exported = tracer()
    client = Mock()
    client.inspect_conversation.return_value = inspection_response()
    monitor = CiscoMonitor(request(), SECRET, t, client_factory=lambda secret: client)

    def fail_output(*args):
        raise ValueError("CREDENTIAL_SENTINEL PRIVATE_SYSTEM_SENTINEL")

    monkeypatch.setattr("chat_runtime.cisco._inspection_output", fail_output)
    with caplog.at_level(logging.INFO, logger="agentcore_chat"):
        monitor.inspect("output", [{"role": "user", "content": "Question"}])
    assert monitor.status == "findings"
    span = exported.get_finished_spans()[0]
    assert span.attributes["cisco.inspection.id"] == "inspection-event-1"
    assert "gen_ai.output.messages" not in span.attributes
    assert "ValueError" in caplog.text
    assert "CREDENTIAL_SENTINEL" not in caplog.text and "PRIVATE_SYSTEM_SENTINEL" not in caplog.text


def test_cisco_input_preserves_full_dialogue_and_redacts_only_configured_key():
    t, exported = tracer()
    client = Mock()
    client.inspect_conversation.return_value = inspection_response()
    monitor = CiscoMonitor(request(), SECRET, t, client_factory=lambda secret: client)
    original = '雪"\\\n' * 8000 + SECRET["api_key"]
    monitor.inspect("input", [
        {"role": "system", "content": "PRIVATE_SYSTEM_SENTINEL"},
        {"role": "developer", "content": "PRIVATE_DEVELOPER_SENTINEL"},
        {"role": "user", "content": original},
        {"role": "assistant", "content": "Earlier answer"},
    ])
    span = exported.get_finished_spans()[0]
    captured = json.loads(span.attributes["gen_ai.input.messages"])
    assert captured == [
        {"role": "user", "parts": [{"type": "text", "content": original.replace(SECRET["api_key"], "[REDACTED]")}]},
        {"role": "assistant", "parts": [{"type": "text", "content": "Earlier answer"}]},
    ]
    assert client.inspect_conversation.call_args.kwargs["messages"][0].content == original
    assert "PRIVATE_SYSTEM_SENTINEL" not in span.attributes["gen_ai.input.messages"]
    assert "PRIVATE_DEVELOPER_SENTINEL" not in span.attributes["gen_ai.input.messages"]


def test_cisco_input_formatting_failure_does_not_skip_inspection(monkeypatch, caplog):
    t, exported = tracer()
    client = Mock()
    client.inspect_conversation.return_value = inspection_response()
    monitor = CiscoMonitor(request(), SECRET, t, client_factory=lambda secret: client)

    def fail_input(*args):
        raise ValueError("CREDENTIAL_SENTINEL PRIVATE_PROMPT_SENTINEL")

    monkeypatch.setattr("chat_runtime.cisco._inspection_input", fail_input)
    with caplog.at_level(logging.INFO, logger="agentcore_chat"):
        monitor.inspect("input", [{"role": "user", "content": "Question"}])
    client.inspect_conversation.assert_called_once()
    assert monitor.status == "findings"
    span = exported.get_finished_spans()[0]
    assert "gen_ai.input.messages" not in span.attributes
    assert cisco_output(span)["event_id"] == "inspection-event-1"
    assert "ValueError" in caplog.text
    assert "CREDENTIAL_SENTINEL" not in caplog.text and "PRIVATE_PROMPT_SENTINEL" not in caplog.text


@pytest.mark.asyncio
async def test_input_normalization_error_fails_open_without_provider_call(caplog):
    t, _ = tracer()
    client = Mock()
    monitor = CiscoMonitor(request(), SECRET, t, client_factory=lambda secret: client)
    event = BeforeModelCallEvent(agent=SimpleNamespace(messages=[None], system_prompt="Fixed prompt"))
    with caplog.at_level(logging.INFO, logger="agentcore_chat"):
        await monitor.before_model(event)
    assert event.cancel is False
    assert monitor.status == "error"
    client.inspect_conversation.assert_not_called()
    assert "AttributeError" in caplog.text


@pytest.mark.asyncio
async def test_output_normalization_and_tracing_errors_fail_open(caplog):
    t, _ = tracer()
    client = Mock()
    client.inspect_conversation.return_value = SimpleNamespace(is_safe=True, classifications=[], event_id="event-123")
    monitor = CiscoMonitor(request(), SECRET, t, client_factory=lambda secret: client)
    agent = SimpleNamespace(messages=[{"role": "user", "content": "Question"}], system_prompt="Fixed prompt")
    await monitor.before_model(BeforeModelCallEvent(agent=agent))
    output_event = AfterModelCallEvent(agent=agent, stop_response=AfterModelCallEvent.ModelStopResponse(message=None, stop_reason="end_turn"))
    with caplog.at_level(logging.INFO, logger="agentcore_chat"):
        await monitor.after_model(output_event)
    assert output_event.retry is False
    assert monitor.status == "error"
    assert client.inspect_conversation.call_count == 1
    broken_tracer = Mock()
    broken_tracer.start_as_current_span.side_effect = RuntimeError("secret-bearing tracing failure")
    monitor.tracer = broken_tracer
    input_event = BeforeModelCallEvent(agent=agent)
    with caplog.at_level(logging.INFO, logger="agentcore_chat"):
        await monitor.before_model(input_event)
    assert input_event.cancel is False
    assert "RuntimeError" in caplog.text
    assert "secret-bearing tracing failure" not in caplog.text
