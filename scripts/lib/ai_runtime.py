#!/usr/bin/env python3
from __future__ import annotations

import json
import os
import re
from dataclasses import dataclass
from typing import Any, Dict, List, Optional

from lib.ai_config import (
    resolve_config,
    resolved_api_base,
    resolved_api_key,
    resolved_api_version,
    resolved_litellm_model,
)

try:
    from openai import OpenAI  # type: ignore
except Exception:
    OpenAI = None  # type: ignore

try:
    from litellm import completion  # type: ignore
except Exception:
    completion = None  # type: ignore


@dataclass
class AIResponse:
    output_text: str
    raw_response: Any
    output_parsed: Any = None

    def to_dict(self) -> Dict[str, Any]:
        raw = self.raw_response

        if hasattr(raw, "model_dump"):
            try:
                return raw.model_dump()  # type: ignore[attr-defined]
            except Exception:
                pass

        if isinstance(raw, dict):
            return raw

        return {"output_text": self.output_text}


def _content_to_text(content: Any) -> str:
    if isinstance(content, str):
        return content

    if isinstance(content, list):
        parts: List[str] = []
        for item in content:
            if isinstance(item, dict):
                if item.get("type") == "text":
                    parts.append(str(item.get("text") or ""))
                elif "text" in item:
                    parts.append(str(item.get("text") or ""))
                else:
                    parts.append(json.dumps(item, ensure_ascii=False))
            else:
                parts.append(str(item))
        return "\n".join(p for p in parts if p)

    if content is None:
        return ""

    return str(content)


def normalize_messages(input_payload: Any) -> List[Dict[str, str]]:
    if isinstance(input_payload, str):
        return [{"role": "user", "content": input_payload}]

    if isinstance(input_payload, list):
        out: List[Dict[str, str]] = []

        for item in input_payload:
            if not isinstance(item, dict):
                continue

            role = str(item.get("role") or "user").strip() or "user"
            content = _content_to_text(item.get("content"))

            out.append({"role": role, "content": content})

        return out or [{"role": "user", "content": ""}]

    if isinstance(input_payload, dict):
        role = str(input_payload.get("role") or "user").strip() or "user"
        content = _content_to_text(input_payload.get("content"))
        return [{"role": role, "content": content}]

    return [{"role": "user", "content": str(input_payload)}]


def extract_output_text(resp: Any) -> str:
    if hasattr(resp, "choices"):
        try:
            choices = getattr(resp, "choices")
            if choices:
                msg = choices[0].message
                content = getattr(msg, "content", "")
                return _content_to_text(content).strip()
        except Exception:
            pass

    if isinstance(resp, dict):
        try:
            choices = resp.get("choices") or []
            if choices:
                msg = choices[0].get("message") or {}
                return _content_to_text(msg.get("content")).strip()
        except Exception:
            pass

    return ""


def extract_json_object(text: str) -> Dict[str, Any]:
    text = (text or "").strip()

    if not text:
        raise ValueError("Model returned empty text")

    try:
        obj = json.loads(text)
        if isinstance(obj, dict):
            return obj
    except Exception:
        pass

    fenced = re.search(
        r"```(?:json)?\s*(\{.*?\})\s*```",
        text,
        flags=re.DOTALL | re.IGNORECASE,
    )
    if fenced:
        obj = json.loads(fenced.group(1))
        if isinstance(obj, dict):
            return obj

    cleaned = re.sub(r"^```(?:json)?\s*", "", text, flags=re.IGNORECASE).strip()
    cleaned = re.sub(r"\s*```$", "", cleaned).strip()
    try:
        obj = json.loads(cleaned)
        if isinstance(obj, dict):
            return obj
    except Exception:
        pass

    start = text.find("{")
    if start < 0:
        preview = text[:500].replace("\n", "\\n")
        raise ValueError(f"No JSON object found in model output. Preview: {preview}")

    depth = 0
    in_string = False
    escape = False

    for i in range(start, len(text)):
        ch = text[i]

        if escape:
            escape = False
            continue

        if ch == "\\":
            escape = True
            continue

        if ch == '"':
            in_string = not in_string
            continue

        if in_string:
            continue

        if ch == "{":
            depth += 1
        elif ch == "}":
            depth -= 1
            if depth == 0:
                obj = json.loads(text[start:i + 1])
                if isinstance(obj, dict):
                    return obj
                raise ValueError("JSON output root must be an object")

    preview = text[start:start + 500].replace("\n", "\\n")
    raise ValueError(f"No complete JSON object found in model output. Preview: {preview}")


def _default_json_schema_response_format() -> Dict[str, Any]:
    return {
        "type": "json_schema",
        "json_schema": {
            "name": "vision360_json_object",
            "schema": {
                "type": "object",
                "additionalProperties": True,
            },
            "strict": False,
        },
    }


def _normalized_response_format(value: Any) -> Optional[Dict[str, Any]]:
    """Normalize response_format values safely for LM Studio/OpenAI-compatible servers.

    LM Studio's OpenAI-compatible chat endpoint rejects the legacy OpenAI
    value {"type": "json_object"} in some versions and returns:
    "response_format.type must be json_schema or text". To avoid that hard
    failure, json_object is upgraded to a permissive json_schema. Empty values
    disable response_format and rely on prompt-level JSON plus parser checks.
    """
    if value is None or value == "":
        return None

    if isinstance(value, str):
        mode = value.strip().lower()
        if not mode:
            return None
        if mode == "json_object":
            return _default_json_schema_response_format()
        if mode == "json_schema":
            return _default_json_schema_response_format()
        if mode == "text":
            return {"type": "text"}
        return None

    if isinstance(value, dict):
        mode = str(value.get("type") or "").strip().lower()
        if not mode:
            return None
        if mode == "json_object":
            return _default_json_schema_response_format()
        if mode == "json_schema":
            return value
        if mode == "text":
            return {"type": "text"}

    return None

class AIRuntime:
    def __init__(
        self,
        task: Optional[str] = None,
        profile: Optional[str] = None,
        api_key: Optional[str] = None,
        api_base: Optional[str] = None,
    ) -> None:
        self.config = resolve_config(
            task_name=task or os.getenv("AI_TASK", "").strip() or None,
            profile_name=profile,
        )

        self.provider = str(self.config.get("provider") or "openai").strip().lower()

        self.model = str(self.config.get("model") or "").strip()
        if not self.model:
            self.model = resolved_litellm_model(self.config)

        self.litellm_model = resolved_litellm_model(self.config)

        self.api_key = resolved_api_key(self.config, explicit_api_key=api_key)
        self.api_base = (api_base or resolved_api_base(self.config) or "").strip()
        self.api_version = resolved_api_version(self.config)

        self.timeout_s = int(self.config.get("timeout_s") or 30)

        self._debug = os.getenv("AI_RUNTIME_DEBUG", "").strip().lower() in {
            "1",
            "true",
            "yes",
            "on",
        }

        if self._debug:
            print(
                "[AI_RUNTIME] "
                f"provider={self.provider} "
                f"model={self.model} "
                f"litellm_model={self.litellm_model} "
                f"api_base={self.api_base} "
                f"openai_sdk_available={OpenAI is not None} "
                f"litellm_available={completion is not None}"
            )

    def _use_direct_openai(self) -> bool:
        if self.provider == "openai_compatible":
            return True

        if self.provider == "openai" and self.api_base:
            return True

        return False

    def available(self) -> bool:
        if self._use_direct_openai():
            return bool(self.api_key) and OpenAI is not None

        return bool(self.api_key) and completion is not None

    def _completion_kwargs(
        self,
        max_output_tokens: Optional[int] = None,
        reasoning: Optional[Dict[str, Any]] = None,
    ) -> Dict[str, Any]:
        kwargs: Dict[str, Any] = {
            "model": self.litellm_model,
            "timeout": self.timeout_s,
        }

        if self.api_key:
            kwargs["api_key"] = self.api_key

        if self.api_base:
            kwargs["api_base"] = self.api_base

        if self.api_version:
            kwargs["api_version"] = self.api_version

        effort = ""
        if reasoning and isinstance(reasoning, dict):
            effort = str(reasoning.get("effort") or "").strip()

        if not effort:
            effort = str(self.config.get("reasoning_effort") or "").strip()

        if max_output_tokens is None:
            max_output_tokens = int(self.config.get("max_output_tokens") or 0) or None

        if max_output_tokens:
            kwargs["max_tokens"] = int(max_output_tokens)

        response_format = _normalized_response_format(self.config.get("response_format"))
        if response_format:
            kwargs["response_format"] = response_format

        temperature = self.config.get("temperature")
        if temperature is not None:
            kwargs["temperature"] = temperature

        if effort and self.provider in {
            "openai",
            "azure",
            "anthropic",
            "gemini",
            "mistral",
            "openrouter",
        }:
            kwargs["reasoning_effort"] = effort

        return kwargs

    def _create_via_openai_sdk(
        self,
        input: Any,
        model: Optional[str] = None,
        max_output_tokens: Optional[int] = None,
    ) -> AIResponse:
        if OpenAI is None:
            raise RuntimeError(
                "openai SDK is not installed or could not be imported. "
                "Install dependencies from requirements/ai-runtime.txt."
            )

        if not self.api_key:
            raise RuntimeError(
                f"Missing API key in env var: {self.config.get('api_key_env_var')}"
            )

        client_kwargs: Dict[str, Any] = {"api_key": self.api_key}

        if self.api_base:
            client_kwargs["base_url"] = self.api_base

        client = OpenAI(**client_kwargs)

        messages = normalize_messages(input)

        selected_model = (model or self.model or "").strip()
        if not selected_model:
            raise RuntimeError("AI model is empty after config resolution")

        kwargs: Dict[str, Any] = {
            "model": selected_model,
            "messages": messages,
            "timeout": self.timeout_s,
        }

        if max_output_tokens is None:
            max_output_tokens = int(self.config.get("max_output_tokens") or 0) or None

        if max_output_tokens:
            kwargs["max_tokens"] = int(max_output_tokens)

        response_format = _normalized_response_format(self.config.get("response_format"))
        if response_format:
            kwargs["response_format"] = response_format

        temperature = self.config.get("temperature")
        if temperature is not None:
            kwargs["temperature"] = temperature

        if self._debug:
            print(
                "[AI_RUNTIME] using OpenAI SDK direct route "
                f"model={selected_model} api_base={self.api_base}"
            )

        try:
            resp = client.chat.completions.create(**kwargs)
        except Exception as exc:
            msg = str(exc)
            if "response_format" in kwargs and "response_format" in msg:
                fallback_kwargs = dict(kwargs)
                fallback_kwargs.pop("response_format", None)
                if self._debug:
                    print(
                        "[AI_RUNTIME][WARN] response_format rejected by endpoint; "
                        "retrying once without response_format"
                    )
                resp = client.chat.completions.create(**fallback_kwargs)
            else:
                raise

        output_text = extract_output_text(resp)
        if self._debug:
            finish_reason = ""
            try:
                choices = getattr(resp, "choices", None) or []
                if choices:
                    finish_reason = str(getattr(choices[0], "finish_reason", "") or "")
            except Exception:
                finish_reason = ""
            print(f"[AI_RUNTIME] response_text_len={len(output_text)} finish_reason={finish_reason}")

        return AIResponse(output_text=output_text, raw_response=resp)

    def create(
        self,
        input: Any,
        model: Optional[str] = None,
        max_output_tokens: Optional[int] = None,
        reasoning: Optional[Dict[str, Any]] = None,
    ) -> AIResponse:
        if self._use_direct_openai():
            return self._create_via_openai_sdk(
                input=input,
                model=model or self.model,
                max_output_tokens=max_output_tokens,
            )

        if completion is None:
            raise RuntimeError(
                "litellm is not installed; install dependencies from requirements/ai-runtime.txt"
            )

        if not self.api_key:
            raise RuntimeError(
                f"Missing API key in env var: {self.config.get('api_key_env_var')}"
            )

        messages = normalize_messages(input)
        kwargs = self._completion_kwargs(
            max_output_tokens=max_output_tokens,
            reasoning=reasoning,
        )

        if model:
            kwargs["model"] = model

        if self._debug:
            print(
                "[AI_RUNTIME] using LiteLLM route "
                f"model={kwargs.get('model')} api_base={kwargs.get('api_base', '')}"
            )

        resp = completion(messages=messages, **kwargs)
        return AIResponse(output_text=extract_output_text(resp), raw_response=resp)

    def parse(
        self,
        input: Any,
        text_format: Any,
        model: Optional[str] = None,
        max_output_tokens: Optional[int] = None,
        reasoning: Optional[Dict[str, Any]] = None,
    ) -> AIResponse:
        resp = self.create(
            input=input,
            model=model,
            max_output_tokens=max_output_tokens,
            reasoning=reasoning,
        )

        obj = extract_json_object(resp.output_text)

        parsed = None
        if text_format is not None:
            if hasattr(text_format, "model_validate"):
                parsed = text_format.model_validate(obj)
            elif hasattr(text_format, "parse_obj"):
                parsed = text_format.parse_obj(obj)
            else:
                parsed = obj

        return AIResponse(
            output_text=resp.output_text,
            raw_response=resp.raw_response,
            output_parsed=parsed,
        )