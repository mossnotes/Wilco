import os
from app.config import settings
from browser_use.config import CONFIG


def test_telemetry_disabled_by_default():
    """Verify that telemetry is disabled in settings, the environment, and browser-use."""
    assert settings.ANONYMIZED_TELEMETRY is False
    assert os.environ.get("ANONYMIZED_TELEMETRY", "").lower() in ("false", "0", "no")
    assert CONFIG.ANONYMIZED_TELEMETRY is False


def test_telemetry_setting_sync():
    """Verify that updating ANONYMIZED_TELEMETRY updates os.environ accordingly."""
    original = os.environ.get("ANONYMIZED_TELEMETRY")
    try:
        # Test truthy parsing
        parsed = settings.parse_telemetry_value("true")
        assert parsed is True
        assert os.environ.get("ANONYMIZED_TELEMETRY") == "true"

        # Test falsy parsing
        parsed = settings.parse_telemetry_value("false")
        assert parsed is False
        assert os.environ.get("ANONYMIZED_TELEMETRY") == "false"
    finally:
        if original is not None:
            os.environ["ANONYMIZED_TELEMETRY"] = original
        else:
            os.environ["ANONYMIZED_TELEMETRY"] = "false"

