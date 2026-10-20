import asyncio
import time
import pytest
from unittest.mock import patch

from app.security.totp import (
    InvalidTOTPSeedError,
    generate_totp_code,
    get_safe_totp_code,
    normalize_totp_seed,
)

SAMPLE_SEED = "JBSWY3DPEHPK3PXP"


def test_normalize_totp_seed():
    # Handles spaces, lowercase, hyphens
    assert normalize_totp_seed("jbsw y3dp-ehpk 3pxp") == SAMPLE_SEED

    # Rejects empty seed
    with pytest.raises(InvalidTOTPSeedError, match="cannot be empty"):
        normalize_totp_seed("")

    # Rejects invalid characters (e.g. '8', '9', '0', '1' are invalid in standard Base32)
    with pytest.raises(InvalidTOTPSeedError, match="invalid non-Base32"):
        normalize_totp_seed("JBSWY890EHPK3PXP")


def test_generate_totp_code_structure():
    code, remaining = generate_totp_code(SAMPLE_SEED)

    assert len(code) == 6
    assert code.isdigit()
    assert 1 <= remaining <= 30


def test_generate_totp_code_deterministic_time():
    # Test at fixed epoch timestamp
    # 1700000010 % 30 = 0 -> remaining = 30
    fixed_time = 1700000010.0
    code1, rem1 = generate_totp_code(SAMPLE_SEED, for_time=fixed_time)
    code2, rem2 = generate_totp_code(SAMPLE_SEED, for_time=fixed_time)

    assert code1 == code2
    assert rem1 == 30
    assert rem2 == 30

    # 1700000030 % 30 = 20 -> remaining = 10
    code3, rem3 = generate_totp_code(SAMPLE_SEED, for_time=1700000030.0)
    assert rem3 == 10


@pytest.mark.asyncio
async def test_get_safe_totp_code_immediate():
    # If plenty of time remaining in window, returns code immediately
    # 1700000015 % 30 = 5 -> remaining = 25s
    with patch("app.security.totp.time.time", return_value=1700000015.0):
        code = await get_safe_totp_code(SAMPLE_SEED, min_drift_buffer=5)
        assert len(code) == 6
        assert code.isdigit()


@pytest.mark.asyncio
async def test_get_safe_totp_code_waits_for_next_window():
    # 1700000038 % 30 = 28 -> remaining = 2s, which is < min_drift_buffer (5s)
    times = [1700000038.0, 1700000041.0]

    def mock_time():
        return times.pop(0) if times else 1700000041.0

    with patch("app.security.totp.time.time", side_effect=mock_time):
        with patch("app.security.totp.asyncio.sleep", return_value=None) as mock_sleep:
            code = await get_safe_totp_code(SAMPLE_SEED, min_drift_buffer=5)
            # Sleep was called to advance window
            assert mock_sleep.called
            assert len(code) == 6
