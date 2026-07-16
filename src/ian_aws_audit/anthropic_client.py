from __future__ import annotations

import os

from anthropic import Anthropic, APIStatusError, APIConnectionError, RateLimitError

DEFAULT_MODEL = os.environ.get("ANTHROPIC_AUDIT_MODEL", "claude-sonnet-4-6")


class AuditModelError(RuntimeError):
    pass


class Client:
    def __init__(self, api_key: str | None = None, model: str = DEFAULT_MODEL, timeout: float = 180.0):
        key = api_key or os.environ.get("ANTHROPIC_API_KEY")
        if not key:
            raise AuditModelError("ANTHROPIC_API_KEY not set")
        self._client = Anthropic(api_key=key, timeout=timeout)
        self.model = model

    def messages(self, prompt: str, system: str | None = None, max_tokens: int = 6000) -> str:
        try:
            resp = self._client.messages.create(
                model=self.model,
                max_tokens=max_tokens,
                system=system or "",
                messages=[{"role": "user", "content": prompt}],
            )
        except RateLimitError as e:
            raise AuditModelError(f"Anthropic rate limited: {e}") from e
        except APIConnectionError as e:
            raise AuditModelError(f"Anthropic connection failed: {e}") from e
        except APIStatusError as e:
            raise AuditModelError(f"Anthropic API error ({e.status_code}): {e.message}") from e

        return "".join(block.text for block in resp.content if block.type == "text")
