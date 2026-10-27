"""Check Splunk control auth with one synthetic prompt; never enforce a verdict.

Reads the app token into memory from Secrets Manager and sends it only to the
fixed Splunk us1 API. Does not invoke Nova or Cisco, or change any control.
"""

import argparse
import asyncio
from datetime import datetime, timezone
import json
from pathlib import Path
import sys
from uuid import uuid4

import boto3
from httpx import HTTPStatusError
from agent_control import agents
from agent_control_models import Agent, Step

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "agent"))
from chat_runtime.config import validate_splunk_secret
from chat_runtime.diagnostics import quiet_dependency_logs, safe_error_code
from chat_runtime.splunk_control import (
    AGENT_NAME, TARGET_ID, TARGET_TYPE, evaluate_server_control, make_client, summarize_result,
)


async def check(secret, register_agent=False):
    exchanges = []

    async def response_status(response):
        # Do not record headers, query strings, credentials, or response bodies.
        exchanges.append({"path": response.request.url.path, "status": response.status_code})

    report = {
        "checkedAt": datetime.now(timezone.utc).isoformat(),
        "targetType": TARGET_TYPE, "targetId": TARGET_ID,
        "credentialSource": "Secrets Manager", "credentialPrinted": False,
        "agentSideEnforcement": False, "requests": exchanges,
    }
    try:
        async with asyncio.timeout(15):
            async with make_client(secret) as client:
                client.http_client.event_hooks["response"].append(response_status)
                if register_agent:
                    # Provision only the missing metadata record. Never overwrite
                    # an existing registration or modify policies/control bindings.
                    try:
                        await agents.get_agent(client, AGENT_NAME)
                        report["agentRegistration"] = "already_present"
                    except HTTPStatusError as error:
                        if error.response.status_code != 404:
                            raise
                        registration = await agents.register_agent(
                            client,
                            Agent(agent_name=AGENT_NAME,
                                  agent_description="AgentCore Chat Lab; observe-only prompt checks"),
                            steps=[], conflict_mode="strict",
                            target_type=TARGET_TYPE, target_id=TARGET_ID,
                        )
                        report["agentRegistration"] = "created" if registration.get("created") else "present"
                result = await evaluate_server_control(
                    client, AGENT_NAME,
                    Step(type="llm", name="chat", input=[{
                        "role": "user", "content": "Say hello in one sentence.",
                    }], context={"request_id": str(uuid4()), "source": "synthetic-preflight"}),
                    "pre", target_type=TARGET_TYPE, target_id=TARGET_ID,
                )
        report.update(status="accepted", isSafe=result.is_safe,
                      matches=len(result.matches or []), errors=len(result.errors or []),
                      nonMatches=len(result.non_matches or []))
        summary = summarize_result(result, secret["o11y_token"])
        report["controlResults"] = summary
        evaluated = summary["matches"] + summary["non_matches"]
        report["configuredControlEvaluated"] = any(
            item.get("control_id") == 229 and not item["error"]
            and item.get("control_execution_id") for item in evaluated
        ) and summary["error_count"] == 0
    except Exception as error:
        report.update(status="error", errorType=safe_error_code(error))
        if isinstance(error, HTTPStatusError):
            report["httpStatus"] = error.response.status_code
            # Classify only. Never persist or print free-text server errors.
            body = error.response.text.lower()
            report["failureCategory"] = (
                "agent_not_registered" if "agent" in body and "not found" in body
                else "target_not_found" if any(word in body for word in ("target", "log_stream")) and "not found" in body
                else "unspecified_not_found" if error.response.status_code == 404
                else "http_error"
            )
    return report


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--profile", default="aidefense")
    parser.add_argument("--register-agent", action="store_true",
                        help="Provision missing Splunk agent metadata once using strict conflict handling")
    args = parser.parse_args()
    quiet_dependency_logs()
    session = boto3.Session(profile_name=args.profile, region_name="us-east-1")
    if session.client("sts").get_caller_identity()["Account"] != "774569412819":
        raise SystemExit("Wrong AWS account; expected 774569412819")
    raw = session.client("secretsmanager").get_secret_value(
        SecretId="/agentcore-chat-lab/splunk",
    )["SecretString"].strip()
    value = json.loads(raw) if raw.startswith(("{", '"')) else raw
    if isinstance(value, str):
        value = {"realm": "us1", "o11y_token": value}
    secret = validate_splunk_secret(value)
    if secret is None:
        raise SystemExit("Splunk secret is not configured")
    report = asyncio.run(check(secret, args.register_agent))
    output = Path(__file__).resolve().parents[1] / "evidence" / "splunk-control-preflight.json"
    output.write_text(json.dumps(report, indent=2) + "\n")
    print(json.dumps(report))
    return 0 if report["status"] == "accepted" and report.get("configuredControlEvaluated") else 1


if __name__ == "__main__":
    raise SystemExit(main())
