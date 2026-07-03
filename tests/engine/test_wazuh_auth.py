from pathlib import Path

from scripts import wazuh_auth


class _Response:
    def raise_for_status(self):
        return None

    def json(self):
        return {"access_token": "test-token"}


def test_fetch_token_uses_ca_without_exposing_api_key(monkeypatch, tmp_path):
    ca = tmp_path / "ca.crt"
    ca.write_text("test-ca", encoding="utf-8")
    captured = {}

    def fake_post(url, **kwargs):
        captured["url"] = url
        captured.update(kwargs)
        return _Response()

    tls_context = object()
    monkeypatch.setattr(
        wazuh_auth.ssl,
        "create_default_context",
        lambda *, cafile: tls_context if cafile == str(ca.resolve()) else None,
    )
    monkeypatch.setattr(wazuh_auth.httpx, "post", fake_post)
    result = wazuh_auth.fetch_token(
        "secret-api-key",
        "https://wazuh.example/auth/token",
        ca_bundle=str(ca),
    )

    assert result == {"access_token": "test-token"}
    assert captured["verify"] is tls_context
    assert captured["json"] == {"api_key": "secret-api-key"}
    assert "secret-api-key" not in str(captured["headers"])


def test_invalid_environment_ca_falls_back_to_project_ca(monkeypatch):
    monkeypatch.setenv("WAZUH_MCP_CA_BUNDLE", "/server/only/ca.crt")
    resolved = wazuh_auth.resolve_ca_bundle()
    assert resolved == str((wazuh_auth.PROJECT_ROOT / "mcp-ca.crt").resolve())
    assert Path(resolved).is_file()
