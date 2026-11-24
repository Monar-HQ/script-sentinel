import httpx
import pytest

from scriptsentinel.ai.client import AIClient, AIConfig


def test_explicit_provider_never_borrows_another_provider_key(monkeypatch):
    monkeypatch.setenv("ANTHROPIC_API_KEY", "anthropic-test-key")
    monkeypatch.setenv("OPENAI_API_KEY", "openai-test-key")
    monkeypatch.delenv("AI_API_KEY", raising=False)
    config = AIClient.auto_detect(provider="openai", model="test-model")
    assert config.api_key == "openai-test-key"


@pytest.mark.parametrize("provider", ["openai", "anthropic", "gemini", "custom", "openrouter"])
def test_provider_contracts_with_mock_transport(provider):
    requests = []

    def handler(request):
        requests.append(request)
        if provider == "anthropic":
            return httpx.Response(200, json={"content": [{"text": "{}"}]})
        if provider == "gemini":
            return httpx.Response(
                200, json={"candidates": [{"content": {"parts": [{"text": "{}"}]}}]}
            )
        return httpx.Response(200, json={"choices": [{"message": {"content": "{}"}}]})

    config = AIConfig(provider, "test-only-key", "https://owned-provider.example/v1", "test-model")
    with (
        httpx.Client(transport=httpx.MockTransport(handler)) as transport,
        AIClient(config, http_client=transport) as client,
    ):
        assert client.generate("Advisory system", "Aggregate evidence") == "{}"
    assert len(requests) == 1
    assert "test-only-key" not in str(requests[0].url)


def test_provider_retries_are_bounded(monkeypatch):
    monkeypatch.setattr("scriptsentinel.ai.client.time.sleep", lambda _: None)
    requests = []

    def handler(request):
        requests.append(request)
        return httpx.Response(429)

    with httpx.Client(transport=httpx.MockTransport(handler)) as transport:
        client = AIClient(AIConfig("openai", "test-only-key", None, "test-model"), transport)
        with pytest.raises(httpx.HTTPStatusError):
            client.generate("system", "data")
        with pytest.raises(ValueError, match="budget"):
            client.generate("system", "data")
    assert len(requests) == 2


def test_custom_provider_rejects_remote_plaintext():
    client = AIClient(AIConfig("custom", "test-only-key", "http://other.example/v1", "test-model"))
    with pytest.raises(ValueError, match="HTTPS"):
        client.generate("system", "data")
