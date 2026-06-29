from pathlib import Path


def test_backend_env_example_uses_sentinal_prefix():
    text = (Path(__file__).parents[1] / ".env.example").read_text(encoding="utf-8")
    required = [
        "SENTINAL_API_KEY",
        "SENTINAL_SECRET_KEY",
        "SENTINAL_LOG_LEVEL",
        "SENTINAL_LOG_FORMAT",
        "SENTINAL_BACKEND_CORS_ORIGINS",
        "SENTINAL_HOST",
        "SENTINAL_PORT",
        "SENTINAL_DEFAULT_MAX_PAGES",
        "SENTINAL_DEFAULT_WORKERS",
        "SENTINAL_DEFAULT_TIMEOUT",
        "SENTINAL_USER_AGENT",
    ]
    for name in required:
        assert f"{name}=" in text

    assert "\nAPI_KEY=" not in text
    assert "\nSECRET_KEY=" not in text
