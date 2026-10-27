# Agent runtime

`main.py` is the AgentCore Python 3.13 CodeZip entry point. It uses `BedrockAgentCoreApp`, a fresh Strands agent per request, and the same text-only conversation structure as the basic Strands template. Package `main.py`, `chat_runtime/`, and the Linux ARM64 dependencies from `requirements.txt` at the ZIP root. Use runtime entry point `["main.py"]` and `DISABLE_ADOT_OBSERVABILITY=true` so the application's OpenTelemetry provider owns tracing.

Runtime V7 and DEFAULT endpoint V7 are READY, CloudFormation is UPDATE_COMPLETE, and SSM configuration version 4 enables Splunk controls. The combined INGEST/API token in `/agentcore-chat-lab/splunk` passes JWT exchange and standalone evaluation. Live normal and injection chats and both eight-span traces are verified in the Splunk UI. Evidence is tracked in `../VALIDATION.md`.

Install development dependencies and run the tests from the repository root:

```sh
UV_CACHE_DIR=/private/tmp/agentcore-chat-uv-cache uv venv --python 3.13 agent/.venv
UV_CACHE_DIR=/private/tmp/agentcore-chat-uv-cache uv pip install --python agent/.venv/bin/python -r agent/requirements.txt pytest pytest-asyncio
agent/.venv/bin/python -m pytest tests/python -q
```

Regenerate the production hash lock only when intentionally upgrading dependencies:

```sh
UV_CACHE_DIR=/private/tmp/agentcore-chat-uv-cache uv pip compile agent/requirements.in --python-version 3.13 --python-platform aarch64-manylinux_2_34 --generate-hashes --output-file agent/requirements.txt
```

Environment variables contain references, never credentials:

| Variable | Value |
| --- | --- |
| `APP_CONFIG_PARAMETER` | `/agentcore-chat-lab/config` |
| `CISCO_SECRET_ARN` | ARN of app-specific key as plain text, or JSON containing `api_key`, `inspection_origin`, optional `policy_id` |
| `SPLUNK_SECRET_ARN` | ARN of app-specific token as plain text, or JSON containing `o11y_token`, `realm` |
| `CISCO_INSPECTION_ORIGIN` | Origin for plain-text Cisco keys; defaults to `https://us.api.inspect.aidefense.security.cisco.com` |
| `SPLUNK_REALM` | Realm for plain-text Splunk tokens; defaults to `us1` |
| `AWS_REGION` | `us-east-1` |
| `DISABLE_ADOT_OBSERVABILITY` | `true` |
| `OTEL_SEMCONV_STABILITY_OPT_IN` | `gen_ai_latest_experimental,gen_ai_span_attributes_only` |

JSON secret fields take precedence over the plain-text endpoint/realm environment defaults. JSON-quoted string credentials work like plain text. Malformed object-like JSON is rejected.

The SSM JSON contains `modelId`, `maxTokens` (default 1024), `splunkProject` (`agentcore-chat-lab`), `splunkAgentStream` (`chat`), `captureContent` (`true`), and `splunkControlEnabled` (application default `false`; deployed CDK configuration `true`). Each request rereads SSM and both secret values, so model changes and rotated credentials do not require a code rebuild. Disabled controls make no evaluation call. Empty integration secrets report `unconfigured`; lookup, inspection, evaluation, and export errors produce sanitized diagnostics and leave chat available.

`ParallelPromptMonitor` runs Cisco input inspection and Splunk LLM/PRE control evaluation concurrently and waits for both bounded checks before Nova starts. They receive the same immutable snapshot of user/assistant dialogue, excluding system/developer instructions. The model retains the server system prompt. Cisco uses `ChatInspectionClient.inspect_conversation`, a three-second timeout, and no inspection retries; its after-model hook still inspects the completed assistant reply. Splunk controls currently inspect input only. Cisco `event_id` and per-inspection request IDs are trace attributes; `client_transaction_id` links both phases to the chat request.

Observe-only behavior applies to every result: Cisco Block and Splunk observe/deny/steer decisions, exceptions, and timeouts cannot rewrite messages, cancel generation, or cause a model retry. Unexpected prompt-hook errors are isolated by the composite hook; client cancellation still propagates. The raw runtime completion event exposes `splunkControlStatus` separately from telemetry-export `splunkStatus`; the existing API/browser does not forward this new field. Control status is recorded in traces and sanitized runtime diagnostics.

The `cisco.inspect` span is explicitly classified as a workflow. Its standard Output contains a bounded JSON representation of the parsed SDK inspection response, gated by `captureContent`. Only known response fields are exported; configured Cisco credentials are redacted if unexpectedly echoed. Inspection failures expose a sanitized error result without exception text or HTTP bodies. Response serialization is isolated from inspection accounting, so display failures cannot change a successful inspection's status.

Each inspection also captures `gen_ai.input.messages` from the exact final SDK message list. Splunk's workflow Input shows user/assistant roles and full dialogue; output-phase inspection includes the completed reply and prior dialogue, matching Cisco's actual request. Input capture excludes system/developer instructions and request credentials/metadata, redacts the configured key if echoed in message text, and respects `captureContent=false`. Input formatting failures are isolated so the SDK inspection still executes.

Splunk uses native Strands OpenTelemetry spans, the SDK's O11y exporter builder, and `SplunkAOSpanProcessor`. Strands' native `gen_ai_span_attributes_only` option places content directly on span attributes for backend compatibility. The outer `chat.turn` workflow records full input history and the completed assistant reply; model identity and token usage remain on nested Strands spans. Tokens pass directly to the SDK from Secrets Manager; they are not exported to process environment variables or written to SDK configuration files. Trace export flush has a four-second application wait limit. `accepted` means the SDK observed a successful ingest acknowledgement; it does not prove downstream indexing or visibility in the Splunk UI. Full conversation content is exported by default; set `captureContent=false` to strip message attributes and events before export while retaining usage and correlation metadata.

System/developer instructions are removed before spans reach Splunk's processor, including native instruction attributes and legacy structured message/event forms. User/assistant text remains intact; the model still receives its original system instructions. Previously exported traces are not changed.

The entry point imports `agent-control-sdk==8.14.0` before V2 snapshotting. `SplunkControlMonitor` creates a request-scoped public SDK client and uses JWT-aware `post_runtime_evaluation` with typed `EvaluationRequest`/`EvaluationResult` models. It targets agent `agentcore-chat-lab`, stage `pre`, `Step(type="llm", name="chat")`, and fixed target `log_stream` / `80fbc697-e69a-4feb-87e7-19f7c7bc92da`. Valid active, recording application spans supply `X-Trace-Id` / `X-Span-Id`; standalone preflight calls send no invented trace/span IDs. The check's application deadline is 15 seconds; SDK HTTP timeout is 12 seconds. No global `agent_control.init()`, decorators, automatic enforcement, or second tracing provider is installed. Import remains free of initialization, sockets, and background threads. The hash lock includes required evaluator/model packages without optional framework, OTel, or Galileo extras.

Control credentials need both INGEST access for traces and API authorization for evaluation. The API role needs `o11y_use_control_runtime_project_shared` plus Owner or Editor access to the target project, or the documented `agent_observability_admin` preset. See [token setup](https://agent-observability-docs.splunk.com/references/faqs/find-keys), [capabilities](https://agent-observability-docs.splunk.com/saas/capabilities), and [JWT runtime configuration](https://agent-observability-docs.splunk.com/how-to-guides/agent-control/initialize-and-configure-agent-control). Select INGEST and API when creating a replacement token; the current console does not allow editing existing authorization scopes. Store the replacement in the same plain-text Secrets Manager entry. The combined token now passes JWT exchange and control evaluation.

From the repository root, `agent/.venv/bin/python scripts/check-splunk-control.py --profile aidefense` runs one synthetic Splunk-only preflight and saves sanitized evidence to `evidence/splunk-control-preflight.json`. For an `aws login` profile, first add the local CRT credential helper with `uv pip install --python agent/.venv/bin/python 'boto3[crt]==1.43.117'`. The preflight requires AWS identity lookup/secret-read access and Splunk's API evaluation permissions; it never invokes Nova/Cisco or changes controls. For initial setup only, add `--register-agent` with API permission to read/create agent metadata: public SDK `agents.get_agent` / `agents.register_agent` provision a missing `agentcore-chat-lab` record with strict conflict handling and fixed stream target, leaving existing records, policies, and controls untouched. This one-time registration is complete. The successful preflight evaluated control 229 with action `observe`, `matched=false`, zero errors, and execution ID `bc1c610a-51a9-4150-b79b-54f8601beb72`.

`splunk.control.check` is a workflow with canonical dialogue Input and sanitized result Output. Native `splunk.control.result` children retain control IDs, stage, action, matched/confidence values, and request/conversation/trace correlation. Free-text evaluator reasons, metadata, and steering instructions are excluded. Both record observe mode and `enforced=false`. `captureContent=false` removes their Input/Output from final exported spans without disabling checks; the vendors still receive the bounded dialogue for evaluation. Usage and correlation remain available.

The Linux ARM64 build target is `aarch64-manylinux_2_34`, matching the hash lock and AgentCore Python 3.13's Amazon Linux 2023 environment. This permits the SDK's RE2 wheel (minimum glibc 2.26) while retaining wheel-only, hash-verified installs and ELF ARM64 validation.

The Python suite passes **88 tests**, with network connections prohibited. Coverage includes actual Strands streaming/hook behavior, concurrent check timing, unchanged replies for Observe/Block/Steer and errors/timeouts, Cisco response inspection, SDK JWT request shape and active-span correlation, secret rotation, Splunk acknowledgement/failure handling, final serialized export privacy, trace content/usage/correlation, input bounds, and safe diagnostics.

Live V7 diagnostics recorded normal Cisco/Splunk prompt checks as `ok` (636/909 ms) and Cisco response inspection as `ok` (111 ms). Injection request `97a5e3ae-3334-4654-8178-6c084e5e1f99`, trace `50e6835edb79472f3fb74108aab4870b`, produced findings from both prompt checks (265/543 ms) with overlapping execution. Cisco input returned `is_safe=false`, action `Allow`, and `SECURITY_VIOLATION` / `PromptInjection`. Nova ran for 541.3 ms with 94 input / 46 output tokens and returned its own refusal; Cisco output was `ok` (121 ms), with accepted trace export. No application block occurred.

Splunk UI confirmed eight spans in both the normal trace `243a8fe8e5128283e86c0d5bb7afd042` and injection trace above, for conversation `94e5f3c5-6899-402f-9a54-aac6a9744211`. The native injection control shows **Triggered / PromptInjectionSLM / 100%**, action `observe`, `matched=true`, confidence `0.9999485577879091`, and zero errors; workflow Output confirms `mode=observe`, `enforced=false`. The normal evaluator score `0.10668888697022906` is below threshold `0.5`, yielding `matched=false` / non-match. Screenshots: [injection workflow](../evidence/splunk-observe-injection-workflow.png), [native control](../evidence/splunk-observe-injection-control.png), and [normal workflow](../evidence/splunk-observe-normal-workflow.png). Future cloud deny/steer decisions still cannot alter, cancel, or retry the model call in this observe-only implementation.
