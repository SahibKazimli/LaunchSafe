"""LLM provider factory.

Single place to swap between Gemini and Claude.  Every agent/tool that
needs an LLM calls :func:`get_llm` instead of instantiating a provider
directly.

Provider selection
------------------
1. If ``LAUNCHSAFE_LLM_MODEL`` starts with ``gemini`` → use Gemini
   (``GEMINI_API_KEY``).
2. Otherwise → Anthropic Claude (``ANTHROPIC_API_KEY``) — this is the
   default in :mod:`core.config`.

Example overrides::

    LAUNCHSAFE_LLM_MODEL=claude-haiku-4-5-20251001   # cheaper / faster
    LAUNCHSAFE_LLM_MODEL=gemini-2.0-flash             # Gemini instead of Claude
"""

from __future__ import annotations

from core.config import LLM_MODEL


def get_llm(max_tokens: int | None = None):
    """Return a LangChain chat model configured for the active provider.

    Parameters
    ----------
    max_tokens:
        Override the output token budget.  If ``None``, the provider's
        own default applies.

    Returns
    -------
    A LangChain ``BaseChatModel`` instance (Gemini or Anthropic).
    """
    model = LLM_MODEL
    kwargs: dict = {"temperature": 0}
    if max_tokens is not None:
        kwargs["max_tokens"] = max_tokens

    if _is_gemini(model):
        return _make_gemini(model, **kwargs)
    return _make_anthropic(model, **kwargs)


# Internal helpers

def _is_gemini(model: str) -> bool:
    return model.lower().startswith("gemini")


def _make_gemini(model: str, **kwargs):
    import os

    try:
        from langchain_google_genai import ChatGoogleGenerativeAI
    except ImportError as exc:
        raise RuntimeError(
            "langchain-google-genai is not installed. "
            "Run: pip install langchain-google-genai"
        ) from exc

    # langchain-google-genai uses max_output_tokens internally but accepts
    # max_tokens as an alias in recent versions. We map it explicitly to
    # be safe.
    max_tokens = kwargs.pop("max_tokens", None)
    if max_tokens is not None:
        kwargs["max_output_tokens"] = max_tokens

    if "api_key" not in kwargs and os.environ.get("GEMINI_API_KEY"):
        kwargs["api_key"] = os.environ.get("GEMINI_API_KEY")

    return ChatGoogleGenerativeAI(model=model, **kwargs)


def _make_anthropic(model: str, **kwargs):
    try:
        from langchain_anthropic import ChatAnthropic
    except ImportError as exc:
        raise RuntimeError(
            "langchain-anthropic is not installed. "
            "Run: pip install langchain-anthropic"
        ) from exc

    return ChatAnthropic(model=model, **kwargs)
