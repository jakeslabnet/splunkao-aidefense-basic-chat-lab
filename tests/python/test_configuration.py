from types import SimpleNamespace
from unittest.mock import Mock
import json

from botocore.exceptions import ClientError
import pytest

from chat_runtime.config import AwsConfiguration


class NoCurrentSecretVersion(Exception):
    pass


def test_empty_secret_container_is_unconfigured(monkeypatch):
    configuration = AwsConfiguration()
    client = Mock()
    client.exceptions = SimpleNamespace(ResourceNotFoundException=NoCurrentSecretVersion)
    client.get_secret_value.side_effect = NoCurrentSecretVersion("No current version")
    monkeypatch.setenv("CISCO_SECRET_ARN", "arn:aws:secretsmanager:us-east-1:123456789012:secret:empty")
    monkeypatch.setattr(configuration, "client", lambda service: client)
    assert configuration.secret("CISCO_SECRET_ARN") is None


def test_secret_access_denied_remains_an_error(monkeypatch):
    configuration = AwsConfiguration()
    client = Mock()
    client.exceptions = SimpleNamespace(ResourceNotFoundException=NoCurrentSecretVersion)
    client.get_secret_value.side_effect = ClientError({"Error": {"Code": "AccessDeniedException", "Message": "Access denied"}}, "GetSecretValue")
    monkeypatch.setenv("SPLUNK_SECRET_ARN", "arn:aws:secretsmanager:us-east-1:123456789012:secret:denied")
    monkeypatch.setattr(configuration, "client", lambda service: client)
    with pytest.raises(ClientError):
        configuration.secret("SPLUNK_SECRET_ARN")


def configuration_with_value(monkeypatch, variable, value):
    configuration = AwsConfiguration()
    client = Mock()
    client.exceptions = SimpleNamespace(ResourceNotFoundException=NoCurrentSecretVersion)
    client.get_secret_value.return_value = {"SecretString": value}
    monkeypatch.setenv(variable, "arn:aws:secretsmanager:us-east-1:123456789012:secret:test")
    monkeypatch.setattr(configuration, "client", lambda service: client)
    return configuration


@pytest.mark.parametrize("quoted", [False, True])
@pytest.mark.parametrize("variable,key,setting,default,override", [
    ("CISCO_SECRET_ARN", "api_key", "CISCO_INSPECTION_ORIGIN", "https://us.api.inspect.aidefense.security.cisco.com", "https://eu.api.inspect.aidefense.security.cisco.com"),
    ("SPLUNK_SECRET_ARN", "o11y_token", "SPLUNK_REALM", "us1", "eu0"),
])
def test_plain_and_json_string_secret_defaults_and_environment(monkeypatch, quoted, variable, key, setting, default, override):
    token = "unit-test-credential-placeholder"
    raw = json.dumps(token) if quoted else token
    configuration = configuration_with_value(monkeypatch, variable, raw)
    monkeypatch.delenv(setting, raising=False)
    endpoint_key = "inspection_origin" if variable == "CISCO_SECRET_ARN" else "realm"
    assert configuration.secret(variable) == {key: token, endpoint_key: default}
    monkeypatch.setenv(setting, override)
    assert configuration.secret(variable) == {key: token, endpoint_key: override}


@pytest.mark.parametrize("variable,value,setting", [
    ("CISCO_SECRET_ARN", {"api_key": "test-placeholder", "inspection_origin": "https://eu.api.inspect.aidefense.security.cisco.com", "policy_id": "test-policy"}, "CISCO_INSPECTION_ORIGIN"),
    ("SPLUNK_SECRET_ARN", {"o11y_token": "test-placeholder", "realm": "eu0"}, "SPLUNK_REALM"),
])
def test_json_secret_explicit_fields_override_environment(monkeypatch, variable, value, setting):
    monkeypatch.setenv(setting, "ignored-setting")
    configuration = configuration_with_value(monkeypatch, variable, json.dumps(value))
    assert configuration.secret(variable) == value


@pytest.mark.parametrize("value", ['{"api_key": broken}', '["credential"]', '"unterminated', '{not-json'])
def test_malformed_or_unsupported_json_cannot_become_a_plain_credential(monkeypatch, value):
    configuration = configuration_with_value(monkeypatch, "CISCO_SECRET_ARN", value)
    with pytest.raises(ValueError, match="Invalid integration secret"):
        configuration.secret("CISCO_SECRET_ARN")
