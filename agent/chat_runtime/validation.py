"""Validate the private adapter-to-runtime contract before using model input."""

from dataclasses import dataclass
import re
from typing import Any
from uuid import UUID

MAX_MESSAGES = 40
MAX_HISTORY_BYTES = 64 * 1024


class InvalidRequest(ValueError):
    """An invocation does not match the application contract."""


@dataclass(frozen=True)
class ChatRequest:
    request_id: str
    conversation_id: str
    user_id: str
    messages: list[dict[str, str]]


def canonical_uuid(value: Any) -> str:
    if not isinstance(value, str):
        raise InvalidRequest("Invalid identifier")
    try:
        parsed = UUID(value)
    except (ValueError, AttributeError) as error:
        raise InvalidRequest("Invalid identifier") from error
    if str(parsed) != value:
        raise InvalidRequest("Invalid identifier")
    return str(parsed)


def validate_request(payload: Any) -> ChatRequest:
    if not isinstance(payload, dict) or set(payload) != {
        "requestId", "conversationId", "userId", "messages"
    }:
        raise InvalidRequest("Invalid request fields")
    request_id = canonical_uuid(payload["requestId"])
    conversation_id = canonical_uuid(payload["conversationId"])
    user_id = payload["userId"]
    if not isinstance(user_id, str) or not re.fullmatch(r"[a-f0-9]{64}", user_id):
        raise InvalidRequest("Invalid user identifier")
    source = payload["messages"]
    if not isinstance(source, list) or not 1 <= len(source) <= MAX_MESSAGES:
        raise InvalidRequest("Invalid history length")
    messages: list[dict[str, str]] = []
    history_bytes = 0
    expected_role = "user"
    for message in source:
        if not isinstance(message, dict) or set(message) != {"role", "content"}:
            raise InvalidRequest("Invalid message fields")
        role, content = message["role"], message["content"]
        if role != expected_role or not isinstance(content, str) or not content.strip():
            raise InvalidRequest("History must alternate user and assistant messages")
        try:
            history_bytes += len(content.encode("utf-8"))
        except UnicodeError as error:
            raise InvalidRequest("Invalid message encoding") from error
        if history_bytes > MAX_HISTORY_BYTES:
            raise InvalidRequest("History exceeds the byte limit")
        messages.append({"role": role, "content": content})
        expected_role = "assistant" if role == "user" else "user"
    if messages[-1]["role"] != "user":
        raise InvalidRequest("The final message must be from the user")
    return ChatRequest(request_id, conversation_id, user_id, messages)


def strands_messages(messages: list[dict[str, str]]) -> list[dict]:
    return [{"role": item["role"], "content": [{"text": item["content"]}]} for item in messages]


def text_messages(messages: list[dict]) -> list[dict[str, str]]:
    """Only send text blocks to Cisco; never stringify tool or binary objects."""
    result = []
    for item in messages:
        role, content = item.get("role"), item.get("content")
        if role not in {"user", "assistant", "system"}:
            continue
        if isinstance(content, str):
            text = content
        elif isinstance(content, list):
            text = "\n".join(
                block["text"] for block in content
                if isinstance(block, dict) and isinstance(block.get("text"), str)
            )
        else:
            continue
        if text.strip():
            result.append({"role": role, "content": text})
    return result
