import pytest
from unittest.mock import patch
from app.config import settings
from app.browser.llm import get_llm


def test_llm_config_defaults():
    assert settings.LLM_PROVIDER == "gemini"
    assert settings.LLM_MODEL == "gemini-3.8-flash"


def test_effective_gemini_api_key(monkeypatch):
    monkeypatch.setattr(settings, "GEMINI_API_KEY", "")
    monkeypatch.setattr(settings, "GOOGLE_API_KEY", "")
    assert settings.effective_gemini_api_key == ""

    monkeypatch.setattr(settings, "GEMINI_API_KEY", "gemini-secret-123")
    assert settings.effective_gemini_api_key == "gemini-secret-123"

    monkeypatch.setattr(settings, "GEMINI_API_KEY", "")
    monkeypatch.setattr(settings, "GOOGLE_API_KEY", "google-secret-456")
    assert settings.effective_gemini_api_key == "google-secret-456"


def test_get_llm_gemini_missing_key(monkeypatch):
    monkeypatch.setattr(settings, "LLM_PROVIDER", "gemini")
    monkeypatch.setattr(settings, "GEMINI_API_KEY", "")
    monkeypatch.setattr(settings, "GOOGLE_API_KEY", "")

    with pytest.raises(ValueError, match="Gemini API key is missing"):
        get_llm()


def test_get_llm_gemini_success(monkeypatch):
    monkeypatch.setattr(settings, "LLM_PROVIDER", "gemini")
    monkeypatch.setattr(settings, "GEMINI_API_KEY", "test-gemini-key")
    monkeypatch.setattr(settings, "LLM_MODEL", "gemini-2.5-flash")

    with patch("app.browser.llm.ChatGoogle") as mock_chat_google:
        mock_instance = mock_chat_google.return_value
        llm = get_llm()
        assert llm == mock_instance
        mock_chat_google.assert_called_once_with(
            model="gemini-2.5-flash",
            api_key="test-gemini-key",
        )


def test_get_llm_openai_missing_key(monkeypatch):
    monkeypatch.setattr(settings, "OPENAI_API_KEY", "")

    with pytest.raises(ValueError, match="OpenAI API key is missing"):
        get_llm(provider="openai")


def test_get_llm_openai_success(monkeypatch):
    monkeypatch.setattr(settings, "OPENAI_API_KEY", "test-openai-key")

    with patch("app.browser.llm.ChatOpenAI") as mock_chat_openai:
        mock_instance = mock_chat_openai.return_value
        llm = get_llm(provider="openai", model="gpt-4o")
        assert llm == mock_instance
        mock_chat_openai.assert_called_once_with(
            model="gpt-4o",
            api_key="test-openai-key",
        )


def test_get_llm_anthropic_missing_key(monkeypatch):
    monkeypatch.setattr(settings, "ANTHROPIC_API_KEY", "")

    with pytest.raises(ValueError, match="Anthropic API key is missing"):
        get_llm(provider="anthropic")


def test_get_llm_anthropic_success(monkeypatch):
    monkeypatch.setattr(settings, "ANTHROPIC_API_KEY", "test-anthropic-key")

    with patch("app.browser.llm.ChatAnthropic") as mock_chat_anthropic:
        mock_instance = mock_chat_anthropic.return_value
        llm = get_llm(provider="anthropic", model="claude-3-5-sonnet-20241022")
        assert llm == mock_instance
        mock_chat_anthropic.assert_called_once_with(
            model="claude-3-5-sonnet-20241022",
            api_key="test-anthropic-key",
        )


def test_get_llm_unsupported_provider():
    with pytest.raises(ValueError, match="Unsupported LLM provider 'unsupported-llm'"):
        get_llm(provider="unsupported-llm")

