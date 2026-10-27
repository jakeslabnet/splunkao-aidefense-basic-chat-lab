"""Request-time configuration and secret retrieval; no expiring snapshot state."""

from dataclasses import dataclass
import json
import os
import re
import threading
from urllib.parse import urlsplit

import boto3
from botocore.config import Config

DEFAULT_MODEL = "amazon.nova-micro-v1:0"
SDK_CONFIG = Config(
    retries={"total_max_attempts": 2, "mode": "adaptive"},
    connect_timeout=3, read_timeout=5,
)


@dataclass(frozen=True)
class AppConfig:
    model_id: str = DEFAULT_MODEL
    max_tokens: int = 1024
    splunk_project: str = "agentcore-chat-lab"
    splunk_agent_stream: str = "chat"
    capture_content: bool = True
    splunk_control_enabled: bool = False


def parse_config(value: str) -> AppConfig:
    data = json.loads(value)
    if not isinstance(data, dict):
        raise ValueError("Invalid application configuration")
    model = data.get("modelId", DEFAULT_MODEL)
    # Model IDs, inference profile IDs, and profile ARNs are administrator-managed.
    if not isinstance(model, str) or not re.fullmatch(r"[A-Za-z0-9_.:/-]{1,2048}", model):
        raise ValueError("Invalid model identifier")
    tokens = data.get("maxTokens", 1024)
    if type(tokens) is not int or not 1 <= tokens <= 4096:
        raise ValueError("Invalid output token limit")
    project = data.get("splunkProject", "agentcore-chat-lab")
    stream = data.get("splunkAgentStream", "chat")
    for name in (project, stream):
        if not isinstance(name, str) or not re.fullmatch(r"[A-Za-z0-9_.-]{1,128}", name):
            raise ValueError("Invalid telemetry destination")
    capture = data.get("captureContent", True)
    if type(capture) is not bool:
        raise ValueError("Invalid content capture setting")
    control_enabled = data.get("splunkControlEnabled", False)
    if type(control_enabled) is not bool:
        raise ValueError("Invalid control observation setting")
    return AppConfig(model, tokens, project, stream, capture, control_enabled)


def validate_cisco_secret(value: dict) -> dict | None:
    if not value.get("api_key") or not value.get("inspection_origin"):
        return None
    origin = value["inspection_origin"]
    if not isinstance(origin, str):
        raise ValueError("Invalid Cisco origin")
    parsed = urlsplit(origin)
    if (parsed.scheme != "https" or not parsed.hostname
            or not parsed.hostname.endswith(".aidefense.security.cisco.com")
            or parsed.port not in (None, 443) or parsed.username or parsed.password
            or parsed.path not in ("", "/") or parsed.query or parsed.fragment):
        raise ValueError("Invalid Cisco origin")
    if not isinstance(value["api_key"], str) or len(value["api_key"]) > 8192:
        raise ValueError("Invalid Cisco key")
    policy_id = value.get("policy_id")
    if policy_id is not None and (not isinstance(policy_id, str)
                                  or not re.fullmatch(r"[A-Za-z0-9_-]{1,128}", policy_id)):
        raise ValueError("Invalid Cisco policy")
    return {"api_key": value["api_key"], "inspection_origin": origin.rstrip("/"), "policy_id": policy_id}


def validate_splunk_secret(value: dict) -> dict | None:
    if not value.get("o11y_token") or not value.get("realm"):
        return None
    if not isinstance(value["realm"], str) or not re.fullmatch(r"[a-z][a-z0-9-]{0,31}", value["realm"]):
        raise ValueError("Invalid Splunk realm")
    if not isinstance(value["o11y_token"], str) or len(value["o11y_token"]) > 8192:
        raise ValueError("Invalid Splunk token")
    return {"o11y_token": value["o11y_token"], "realm": value["realm"]}


class AwsConfiguration:
    """Lazy clients share refreshable role credentials; secret values never enter snapshots."""

    def __init__(self):
        self._clients: dict = {}
        self._lock = threading.Lock()

    def client(self, service: str):
        with self._lock:
            if service not in self._clients:
                self._clients[service] = boto3.client(
                    service, region_name=os.environ.get("AWS_REGION", "us-east-1"), config=SDK_CONFIG,
                )
            return self._clients[service]

    def app_config(self) -> AppConfig:
        response = self.client("ssm").get_parameter(
            Name=os.environ.get("APP_CONFIG_PARAMETER", "/agentcore-chat-lab/config"),
        )
        return parse_config(response["Parameter"]["Value"])

    def secret(self, variable: str) -> dict | None:
        arn = os.environ.get(variable)
        if not arn:
            return None
        client = self.client("secretsmanager")
        try:
            response = client.get_secret_value(SecretId=arn)
        except client.exceptions.ResourceNotFoundException:
            # The deployment intentionally creates empty secret containers first.
            # Secrets Manager reports no current version until a value is added.
            return None
        raw_value = response.get("SecretString", "{}")
        if not isinstance(raw_value, str):
            raise ValueError("Invalid integration secret")
        value = raw_value.strip()
        if value.startswith(("{", "[", '"')):
            # Preserve JSON configuration, including its explicit endpoint/realm.
            # Dict-like malformed JSON must never become an API credential.
            try:
                decoded = json.loads(value)
            except json.JSONDecodeError as error:
                raise ValueError("Invalid integration secret JSON") from error
            if isinstance(decoded, dict):
                return decoded
            if not isinstance(decoded, str):
                raise ValueError("Invalid integration secret")
            value = decoded.strip()
        if variable == "CISCO_SECRET_ARN":
            return {
                "api_key": value,
                "inspection_origin": os.environ.get(
                    "CISCO_INSPECTION_ORIGIN", "https://us.api.inspect.aidefense.security.cisco.com",
                ),
            }
        if variable == "SPLUNK_SECRET_ARN":
            return {"o11y_token": value, "realm": os.environ.get("SPLUNK_REALM", "us1")}
        raise ValueError("Unknown integration secret")
