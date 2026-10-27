# AgentCore Chat Lab

Basic Strands chat on **AgentCore platform V2 / microVM / Python 3.13 / S3 CodeZip**, with Nova Micro, Cisco AI Defense monitor-only inspection, and Splunk Agent Observability. The web UI is served through CloudFront and requires an invited Cognito account.

**Last verified deployment (October 22, 2026):** runtime V7 and the DEFAULT endpoint were READY, CloudFormation was UPDATE_COMPLETE, and SSM configuration version 4 enabled Splunk controls. The combined INGEST/API token was saved in `/agentcore-chat-lab/splunk`. JWT exchange and standalone evaluation returned HTTP 200. Live normal and injection chats, their eight-span traces, and native control results were verified in the Splunk UI.

## Architecture

Browser → CloudFront → Cognito-authorized Regional REST API → streaming Node.js Lambda → IAM-authenticated Python AgentCore runtime → Amazon Bedrock.

The Python runtime runs Cisco input inspection and Splunk Agent Control's LLM/PRE evaluation concurrently before Nova starts. Both receive the same bounded user/assistant dialogue, excluding system/developer instructions; the model retains its system instructions. Cisco also inspects the completed assistant reply. Splunk controls currently check input only. All checks are observe-only: Cisco Block and Splunk deny/steer decisions, timeouts, or errors cannot rewrite, cancel, or retry the model call. Strands traces are exported directly through the Splunk Python SDK. This lab exports full user messages and assistant replies by default; use synthetic conversations.

The application has no tools, durable chat database, NAT gateway, or continuously running server. Chat history exists only in the browser tab's memory. Authentication tokens use sessionStorage; logout and tab closure clear that session. The runtime reconstructs bounded history on every request and uses a user-bound session identifier derived by the trusted API.

## Deployment

Target: account `774569412819`, `us-east-1`, AWS profile `aidefense`. Node.js 22+, Python 3.13+, and `uv` are required. AWS SDKs use the named profile, and deployment tooling checks the account before making changes.

```sh
npm ci
npm --prefix api ci
npm --prefix web ci
npm run build
npm run check
npm run test:infra
npm --prefix api test
npm --prefix web test
npm run deploy
```

`npm run build` downloads hash-locked Python 3.13 Linux ARM64 wheels and validates ELF architecture. It packages `main.py`, `chat_runtime/`, and dependencies at ZIP root. Deployment uploads content-addressed/versioned ZIPs to private S3, deploys the CDK-synthesized CloudFormation stacks, publishes the UI and non-secret browser configuration, and prints the CloudFront URL. AgentCore V2 initialization can take several minutes.

The initial Cognito invitation is sent to `jaruddy@cisco.com`. Complete the first sign-in and password change yourself in the Cognito hosted page. Public signup is disabled. The web app requests `openid email agent-chat/invoke` via authorization code + S256 PKCE.

## Configure Cisco and Splunk

Two app-specific empty secrets are created in Secrets Manager:

- `/agentcore-chat-lab/cisco`: a plain-text inspection key (uses the configured US origin), or JSON fields `api_key`, `inspection_origin`, and optional `policy_id`.
- `/agentcore-chat-lab/splunk`: a plain-text Splunk token (uses configured realm `us1`), or JSON fields `o11y_token` and `realm`. Trace export needs INGEST permission; the control check also needs API authorization.

Enter credentials directly in Secrets Manager, or use the local masked-input helper after installing the Python dependencies:

```sh
uv venv --python 3.13 agent/.venv
uv pip install --python agent/.venv/bin/python -r agent/requirements.txt
agent/.venv/bin/python scripts/configure-integrations.py
```

The helper checks the AWS account, never prints credentials or saves them locally, and sends them only to Secrets Manager. Empty input skips that service. It does not make inspection or telemetry requests. No key/token belongs in `config/lab.json`, CDK context, shell arguments, browser configuration, or source control.

For this deployment the Splunk realm is **`us1`**. In Splunk Observability Cloud:

1. Open **Agent Observability** and confirm your organization is entitled to it and your user has access.
2. The project **`agentcore-chat-lab`** and Agent Stream **`chat`** were created during implementation.
3. Create a replacement in **Settings → Access tokens** with both **INGEST** and **API**. The current console does not let you change the existing token's authorization scopes. For control evaluation, assign an API role with `o11y_use_control_runtime_project_shared` and Owner or Editor access to the target project, or use the documented `agent_observability_admin` preset. The official [token setup](https://agent-observability-docs.splunk.com/references/faqs/find-keys) describes combined INGEST/API access; the [capability reference](https://agent-observability-docs.splunk.com/saas/capabilities) specifies project access requirements. Keep token read access restricted. If rotating, copy the replacement directly into the same Secrets Manager secret as plain text; do not paste it into chat. Rotate it before expiration.

The current combined token has passed JWT exchange and control evaluation. The runtime uses one secret for both purposes; a separate API token would require additional wiring. To rerun the standalone synthetic preflight:

```sh
agent/.venv/bin/python scripts/check-splunk-control.py --profile aidefense
```

For an `aws login` profile, the local Python environment also needs its CRT credential helper: `uv pip install --python agent/.venv/bin/python 'boto3[crt]==1.43.117'`. This local helper is separate from the locked runtime package.

The helper checks the AWS account, reads the token in memory from Secrets Manager, and sends a synthetic prompt only to the fixed Splunk `us1` API. It does not invoke Nova/Cisco or change controls. AWS access needs STS identity lookup and read access to the app's Splunk secret; Splunk needs the API evaluation permissions above. It writes a sanitized report to `evidence/splunk-control-preflight.json`.

Agent metadata for `agentcore-chat-lab` was registered once using the public SDK's `agents.get_agent` / `agents.register_agent` APIs, strict conflict handling, and the fixed target stream. For a fresh setup with permission to read/create agent metadata, run `agent/.venv/bin/python scripts/check-splunk-control.py --profile aidefense --register-agent` once; existing registrations are left untouched. No policy or control binding is changed. The successful preflight evaluated control **229**, returning a non-match with action `observe` and zero errors; see the report for its execution ID. This verifies setup independently of runtime chat.

The default Cisco origin is **`https://us.api.inspect.aidefense.security.cisco.com`**. It is the regional server address, without `/api/v1/inspect/chat`; the SDK appends the route. Verify that your separate inspection key belongs to this region. A Gateway URL or Gateway key is a different integration. Cisco documentation: [regional setup](https://developer.cisco.com/docs/ai-defense-inspection/getting-started/).

The runtime rereads configuration and both secrets on every request, so credential changes do not require a rebuild. Until valid secrets are stored, chat remains usable and integration status indicates it has not succeeded. An SDK export acknowledgement is not proof that a trace is visible in the selected Splunk Agent Stream; verify the destination UI.

Each `cisco.inspect` workflow span exposes its parsed Cisco SDK response in Splunk's **Output** panel when content capture is enabled. Select the input or output inspection using its `cisco.phase` attribute. The JSON includes the verdict, action, severity, classifications, rule results, explanation, and inspection/correlation IDs that Cisco returned. This is a bounded, sanitized SDK response; HTTP headers, credentials, request bodies, and unknown response fields are excluded. Export failures do not change chat behavior. `captureContent=false` also removes these response bodies. A Cisco `action` value reports the API verdict; this application's monitor-only mode continues chat unchanged.

The same span's **Input** panel shows the role-preserving dialogue sent to Cisco. For `cisco.phase=input`, this is the bounded conversation history through the latest user prompt; for `cisco.phase=output`, it also includes the completed assistant reply. The Input is built from the exact final SDK message list, omits system/developer instructions, and redacts the configured inspection key if accidentally included in dialogue. `captureContent=false` removes both Input and Output content. Display failures do not skip inspection or change its outcome.

Strands emits the latest GenAI conventions with its native `gen_ai_span_attributes_only` option so Splunk can display the messages. An export filter removes system-instruction attributes and system/developer messages before the Splunk processor receives spans. The parent turn is a workflow with bounded conversation input and the completed reply; nested Strands/model spans carry model identity and token usage. Incomplete turns do not claim a completed workflow output. Existing Cisco events and Splunk traces created before this filter retain their previously exported content.

Before the first operator-run live SDK validation, review the synthetic test text and the Cisco/Splunk destinations and confirm the credential-bearing sends. Normal user chat sends the entered text to the configured integrations.

The integration uses `agent-control-sdk==8.14.0`'s public JWT-aware `AgentControlClient.post_runtime_evaluation` API with a typed LLM/PRE request for agent `agentcore-chat-lab`, targeting fixed `log_stream` UUID `80fbc697-e69a-4feb-87e7-19f7c7bc92da`. Valid active application spans supply `X-Trace-Id` / `X-Span-Id` for server correlation; standalone preflight calls omit these headers rather than inventing trace IDs. It does not call global `agent_control.init()`, use control decorators, or enable automatic enforcement. See Splunk's [runtime initialization and target configuration](https://agent-observability-docs.splunk.com/how-to-guides/agent-control/initialize-and-configure-agent-control). Static SDK imports happen before V2 snapshotting; client construction and authentication happen during requests.

Trusted SSM flag `splunkControlEnabled` defaults to `false` in application code; the deployed CDK configuration sets it to `true`. Disabled checks make no control API call. Missing or unreadable secrets and check failures leave chat available with a sanitized status. The Splunk check has a 15-second application deadline and a 12-second SDK HTTP timeout. The raw runtime event reports `splunkControlStatus` separately from the trace-export `splunkStatus`; the existing API/browser does not forward this additional field. Check results are recorded in traces and sanitized diagnostics.

The `splunk.control.check` workflow records the inspected dialogue and a sanitized result summary; nested native `splunk.control.result` spans retain control IDs, action, matched state, and correlation IDs. Decisions always record `enforced=false`. `captureContent=false` removes control Input/Output from exported spans while preserving correlation and usage; it does not disable either vendor's checks or remove dialogue from their evaluation requests.

## Change the model

Current default: `amazon.nova-micro-v1:0`, maximum 1,024 output tokens. Non-secret configuration is managed by CDK at `/agentcore-chat-lab/config` in SSM Parameter Store.

```sh
npm run set-model -- amazon.nova-lite-v1:0 arn:aws:bedrock:us-east-1::foundation-model/amazon.nova-lite-v1:0
```

The command updates the managed configuration and scoped Bedrock IAM resources, without rebuilding either ZIP. Confirm the chosen model is available/authorized first. For inference profiles, supply the profile ARN and every underlying foundation-model ARN required by that profile as additional arguments. Start a new chat after changing model families. There is intentionally no browser model override or selector.

## Operations and cost

```sh
npm run status
npm run publish
```

`deployment-outputs.json` contains non-secret URLs and resource IDs and is ignored by Git. Runtime and Lambda logs use seven-day retention. Log groups are encrypted; trace content is exported only to the configured Splunk tenant. Application logs exclude conversation bodies and credentials. Full Splunk trace retention follows the tenant's retention policy.

The **$25 monthly AWS budget is account-wide**, with 50% and 100% actual-spend notifications to `jaruddy@cisco.com`; existing AWS workloads can trigger it. It is an alert, not a spending cap. Cisco/Splunk licensing and ingestion charges are separate. The principal fixed lab costs are the log KMS key and populated Secrets Manager secrets; the remaining services largely charge by usage. Lambda concurrency is limited to 5 and API Gateway to 2 requests/second with burst 5.

CloudFront/API streams send 10-second heartbeats and have a 270-second application deadline. Stop closes the client stream and aborts upstream reading where supported; model execution can continue briefly. Interrupted turns are excluded from subsequent history and are not automatically retried.

## Tests and acceptance

```sh
uv pip install --python agent/.venv/bin/python pytest pytest-asyncio
agent/.venv/bin/python -m pytest tests/python -q
npm run test:infra
npm --prefix api test
npm --prefix web test
```

The Python suite passes **88 tests**. Local tests use mocked dependencies and prohibit integration traffic. They cover real Strands streaming hooks and spans, concurrent prompt checks, unchanged chat for Observe/Block/Steer and failures, Cisco response inspection, native final trace export and content filtering, secure identifiers, input limits, malicious HTML rendering, SSE chunking, cancellation, Cognito claims, and CDK security properties.

Live checks verified runtime/endpoint READY and V2, authorized multi-turn chat, model configuration changes without repackaging, anonymous rejection, private-S3 rejection, two-user session isolation even with a deliberately reused conversation UUID, and correlated Cisco/Splunk trace evidence. The second invited account is `jake@jakeslab.net`. The user waived the over-30-second reply exercise for this demo.

V7 browser chat returned normally with Cisco input `ok` (636 ms), Splunk PRE `ok` (909 ms), and Cisco output `ok` (111 ms). An injection test produced Cisco and Splunk findings (265 ms and 543 ms) with overlapping prompt checks; Nova still ran and returned its own refusal, Cisco output was `ok` (121 ms), and trace export was accepted. The application did not block the request.

Splunk UI verification confirmed eight spans in each trace. The injection's native control result shows **Triggered / PromptInjectionSLM / 100%** (action `observe`, `matched=true`, confidence `0.9999485577879091`, zero errors); workflow Output records `mode=observe` and `enforced=false`. The normal evaluator score was `0.10668888697022906`, below the `0.5` threshold, with a non-match. See [injection workflow](evidence/splunk-observe-injection-workflow.png), [native control result](evidence/splunk-observe-injection-control.png), [normal workflow](evidence/splunk-observe-normal-workflow.png), and `VALIDATION.md` for detailed correlation and deployment evidence. Future cloud deny/steer decisions remain observe-only in this application.

## Cleanup and rollback

```sh
npm run cleanup -- --confirm-delete-app
```

This requests deletion of the application stack. The Cognito user pool, UI bucket, log KMS key, artifact bucket, and integration secrets are retained to avoid silent data/credential loss; these may still incur charges. The storage stack is retained. Permanently deleting retained objects, secret values, users, and the encryption key is a separate deliberate cleanup operation. Review CloudFormation resources and complete that operation only when rollback is no longer needed.

For rollback, restore the previous local configuration and `build/manifest.json` (including versioned ZIP references), synthesize, and redeploy. Retained immutable release artifacts provide the previous code. Do not use CDK hotswap for runtime/model updates.

## Security boundaries

CodeGuard guidance was applied to secret exclusion, TLS certificate verification, cryptographically secure IDs, strict request schemas, safe plain-text rendering, PKCE, scoped IAM, encrypted private storage, and sanitized logs. No certificate checks are disabled and no secrets are embedded. AWS access uses execution roles. CloudFront caches static assets, never authenticated API responses. API failures are not rewritten to the SPA page. Default ADOT injection is explicitly disabled so the application owns one trace provider and Splunk exporter.

## Repository contents

Source, infrastructure, dependency locks, tests, operational scripts, documentation, and three selected synthetic-validation screenshots are versioned. Generated archives, installed dependencies, local credentials, deployment outputs, raw logs, and deployment snapshots stay local and are excluded by `.gitignore`. `VALIDATION.md` references those local evidence files as an operator record.

This is an account-specific lab: its configuration and notes contain AWS account/resource IDs, integration destination IDs, and invitation email addresses. Credentials remain in Secrets Manager. Publishing the repository does not deploy or change the running application.
