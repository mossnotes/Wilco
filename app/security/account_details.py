"""Validate account identifiers without combining phone numbers and calling codes."""

import re
from typing import Literal

import phonenumbers

AccountField = Literal["username", "email", "phone", "country_code"]


def normalize_phone_number(value: str) -> str:
    value = value.strip()
    if value.startswith("+"):
        raise ValueError("Please send just the phone number for the phone field, without a country code.")
    if not value or len(value) > 64 or not re.fullmatch(r"[0-9 ()\-./]+", value):
        raise ValueError("Please send only your phone number, on one line.")
    # Strip visual separators only. Never infer a country, add a dialing prefix,
    # remove leading zeros, or generate an international version of this value.
    digits = re.sub(r"\D", "", value)
    if not 6 <= len(digits) <= 15:
        raise ValueError("Please check the phone number and reply with only the number.")
    return digits


def normalize_country_code(value: str) -> str:
    compact = value.strip()
    if not re.fullmatch(r"\+?[1-9][0-9]{0,2}", compact) or int(compact.lstrip("+")) not in phonenumbers.COUNTRY_CODE_TO_REGION_CODE:
        raise ValueError("Please send only a valid country calling code, such as +1 or +44.")
    return f"+{compact.lstrip('+')}"


def normalize_account_detail(value: str, field: AccountField) -> str:
    value = value.strip()
    if not value or len(value) > 320 or re.search(r"[\x00-\x1f\x7f]", value):
        raise ValueError(f"Please send only your {field}, on one line.")
    if field == "phone":
        return normalize_phone_number(value)
    if field == "country_code":
        return normalize_country_code(value)
    if field == "email":
        if not re.fullmatch(r"[^@\s<>]+@[^@\s<>]+\.[^@\s<>]+", value) or len(value) > 254:
            raise ValueError("Please send a valid email address, on one line.")
    elif field != "username":
        raise ValueError("Unsupported account detail.")
    return value


def account_placeholders(domain_slug: str, field: AccountField, value: str) -> dict[str, str]:
    if field == "phone":
        return {f"{domain_slug}_phone_number": normalize_phone_number(value)}
    return {f"{domain_slug}_{field}": normalize_account_detail(value, field)}
