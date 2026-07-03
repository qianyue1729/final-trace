from trace_agent.llm.client import DeepSeekClient


class _FakeHttpClient:
    def __init__(self, **kwargs):
        self.kwargs = kwargs


class _FakeOpenAI:
    def __init__(self, **kwargs):
        self.kwargs = kwargs
        self.closed = False

    def close(self):
        self.closed = True


def test_tls_verification_enabled_by_default(monkeypatch):
    captured = {}

    def fake_http_client(**kwargs):
        captured.update(kwargs)
        return _FakeHttpClient(**kwargs)

    monkeypatch.setattr("trace_agent.llm.client.httpx.Client", fake_http_client)
    monkeypatch.setattr("trace_agent.llm.client.OpenAI", _FakeOpenAI)
    client = DeepSeekClient(
        base_url="https://model.example/v1",
        api_key="test",
    )
    assert captured["verify"] is True
    client.close()
    assert client._client.closed is True


def test_custom_ca_bundle_is_passed_to_http_client(monkeypatch, tmp_path):
    captured = {}
    ca_bundle = tmp_path / "ca.pem"
    ca_bundle.write_text("test-ca", encoding="utf-8")

    def fake_http_client(**kwargs):
        captured.update(kwargs)
        return _FakeHttpClient(**kwargs)

    monkeypatch.setattr("trace_agent.llm.client.httpx.Client", fake_http_client)
    monkeypatch.setattr("trace_agent.llm.client.OpenAI", _FakeOpenAI)
    DeepSeekClient(
        base_url="https://model.example/v1",
        api_key="test",
        ca_bundle=str(ca_bundle),
    )
    assert captured["verify"] == str(ca_bundle)
