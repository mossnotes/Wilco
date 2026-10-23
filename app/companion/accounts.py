"""Domain-level views of the vault's encrypted, per-field storage."""

from pydantic import BaseModel, ConfigDict, Field

from app.config import settings
from app.security.vault import decrypt_secret

ACCOUNT_FIELDS = ("username", "email", "phone", "country_code")
SECRET_FIELDS = ("password", "api_key", "totp_seed")


class UpdateAccountRequest(BaseModel):
    model_config = ConfigDict(extra="forbid")

    username: str | None = Field(default=None, max_length=320, repr=False)
    email: str | None = Field(default=None, max_length=320, repr=False)
    phone: str | None = Field(default=None, max_length=64, repr=False)
    country_code: str | None = Field(default=None, max_length=10, repr=False)
    password: str | None = Field(default=None, max_length=16384, repr=False)
    api_key: str | None = Field(default=None, max_length=16384, repr=False)
    totp_seed: str | None = Field(default=None, max_length=1024, repr=False)


def account_details(domain, credentials):
    details = {field: "" for field in ACCOUNT_FIELDS}
    for credential in credentials:
        if credential.auth_type in ACCOUNT_FIELDS:
            details[credential.auth_type] = decrypt_secret(credential.encrypted_blob, settings.vault_key_bytes)
    # Older password rows kept an associated login identifier in a separate column.
    for credential in credentials:
        if value := credential.username_or_identifier:
            field = "email" if "@" in value else "username"
            if not details[field]:
                details[field] = value
    return {
        "site_domain": domain,
        "details": details,
        "stored_secrets": [field for field in SECRET_FIELDS if any(c.auth_type == field for c in credentials)],
    }


def group_accounts(credentials):
    return [{"site_domain": domain} for domain in sorted({c.site_domain for c in credentials})]
