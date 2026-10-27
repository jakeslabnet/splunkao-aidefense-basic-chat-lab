"""Allowlisted diagnostics prevent SDK exceptions and secret values leaking to logs."""

import json
import logging
import re

LOGGER = logging.getLogger("agentcore_chat")
LOGGER.setLevel(logging.INFO)
if not LOGGER.handlers:
    handler = logging.StreamHandler()
    handler.setFormatter(logging.Formatter("%(message)s"))
    LOGGER.addHandler(handler)


def safe_error_code(error: BaseException) -> str:
    code = type(error).__name__
    return code if re.fullmatch(r"[A-Za-z][A-Za-z0-9_]{0,79}", code) else "IntegrationError"


def diagnostic(event: str, request_id: str, **fields) -> None:
    allowed = {"integration", "status", "phase", "errorCode", "traceId", "conversationId", "inspectionId", "latencyMs", "classificationCount"}
    record = {"event": event, "requestId": request_id}
    for key, value in fields.items():
        if key not in allowed or not isinstance(value, (str, int, float, bool)):
            continue
        if isinstance(value, str):
            value = re.sub(r"[^A-Za-z0-9_.:-]", "_", value)[:128]
        record[key] = value
    LOGGER.info(json.dumps(record, separators=(",", ":")))


def quiet_dependency_logs() -> None:
    # Some SDK exception logs include request content, response bodies, or headers.
    # The app emits its own allowlisted integration/error events instead.
    for name in ("aidefense_sdk", "splunk_ao", "galileo_core", "agent_control", "agent_control_engine",
                 "opentelemetry", "strands", "httpx", "httpcore"):
        logger = logging.getLogger(name)
        logger.handlers.clear()
        logger.addHandler(logging.NullHandler())
        logger.propagate = False
