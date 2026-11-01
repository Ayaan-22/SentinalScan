import pytest
from fastapi import FastAPI
from fastapi.testclient import TestClient
from starlette.responses import JSONResponse, PlainTextResponse
from starlette.websockets import WebSocketDisconnect

from app.core.security import is_valid_api_key, validate_configured_api_key
from app.main import app
from app.middleware import SensitiveDataSanitizer


def test_configured_api_key_rejects_known_defaults():
    for value in ("", "short", "dev_api_key_12345", "changeme_in_production"):
        with pytest.raises(RuntimeError, match="API_KEY must be at least 32 characters"):
            validate_configured_api_key(value)


def test_constant_time_api_key_helper_accepts_only_correct_key():
    assert is_valid_api_key("ci_test_key_abcdefghijklmnop12345678") is True
    assert is_valid_api_key("wrong_key_here") is False
    assert is_valid_api_key(None) is False


@pytest.mark.parametrize("query", ["", "?api_key=wrong-key"])
def test_websocket_requires_api_key(query):
    client = TestClient(app)
    with (
        pytest.raises(WebSocketDisconnect) as exc_info,
        client.websocket_connect(f"/ws/logs/missing-scan{query}"),
    ):
        pytest.fail("Unauthenticated WebSocket should not connect")
    assert exc_info.value.code == 1008


def test_websocket_accepts_api_key_and_reports_missing_scan():
    client = TestClient(app)
    with client.websocket_connect(
        "/ws/logs/missing-scan?api_key=ci_test_key_abcdefghijklmnop12345678"
    ) as websocket:
        assert websocket.receive_json() == {
            "type": "error",
            "status": "not_found",
            "message": "Scan not found",
        }
        with pytest.raises(WebSocketDisconnect) as exc_info:
            websocket.receive_json()
        assert exc_info.value.code == 1008


def test_sensitive_data_sanitizer_redacts_and_content_length_is_correct():
    test_app = FastAPI()
    test_app.add_middleware(SensitiveDataSanitizer)

    @test_app.get("/json")
    async def json_secret():
        return JSONResponse({"api_key": "super-secret", "ok": True})

    client = TestClient(test_app)
    response = client.get("/json")
    assert response.status_code == 200
    assert "[REDACTED]" in response.text
    assert "super-secret" not in response.text
    assert int(response.headers["content-length"]) == len(response.content)


def test_sensitive_data_sanitizer_leaves_non_json_untouched():
    test_app = FastAPI()
    test_app.add_middleware(SensitiveDataSanitizer)

    @test_app.get("/text")
    async def text_response():
        return PlainTextResponse("api_key=not-json")

    client = TestClient(test_app)
    response = client.get("/text")
    assert response.text == "api_key=not-json"
