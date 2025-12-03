"""Utility for making OpenAI LLM calls with an arbitrary payload."""

from __future__ import annotations

import json
import os
from typing import Any, Dict
from urllib import error, request

API_KEY_ENV = "OPENAI_API_KEY"
API_BASE_ENV = "OPENAI_API_BASE"
DEFAULT_API_BASE = "https://api.openai.com/v1"


def call_openai(payload: Dict[str, Any], endpoint: str = "chat/completions") -> Dict[str, Any]:
    """Send *payload* to the OpenAI API and return the parsed JSON response."""

    api_key = os.getenv(API_KEY_ENV)
    if not api_key:
        raise RuntimeError(f"Environment variable {API_KEY_ENV} is not set")

    api_base = os.getenv(API_BASE_ENV, DEFAULT_API_BASE).rstrip("/")
    url = f"{api_base}/{endpoint.lstrip('/')}"

    body = json.dumps(payload).encode("utf-8")
    req = request.Request(url, data=body, method="POST")
    req.add_header("Authorization", f"Bearer {api_key}")
    req.add_header("Content-Type", "application/json")

    try:
        with request.urlopen(req) as resp:
            return json.loads(resp.read().decode("utf-8"))
    except error.HTTPError as exc:  # Provide API error details to the caller.
        detail = exc.read().decode("utf-8", "ignore")
        raise RuntimeError(f"OpenAI request failed: {exc.code} {exc.reason}: {detail}") from exc
    except error.URLError as exc:
        raise RuntimeError(f"Unable to reach OpenAI API: {exc.reason}") from exc


def execute_llm_call(payload: Dict[str, Any]) -> Dict[str, Any]:
    """Convenience wrapper that calls the API and prints the response."""

    response = call_openai(payload)
    print(json.dumps(response, indent=2))
    return response


if __name__ == "__main__":
    example_payload: Dict[str, Any] = {
        "model": "gpt-4o-mini",
        "messages": [
            {"role": "system", "content": "You are a helpful assistant."},
            {"role": "user", "content": "Hello from evaluation_agent.py"},
        ],
    }

    execute_llm_call(example_payload)
