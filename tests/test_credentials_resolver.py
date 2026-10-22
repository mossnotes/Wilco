import pytest
import pytest_asyncio

from app.browser.credentials_resolver import (
    extract_candidate_domains,
    get_domain_slug,
    credential_scope,
    resolve_task_credentials,
)
from app.config import settings
from app.db.engine import async_session_factory, init_db
from app.db.repository import CredentialRepository, UserRepository
from app.security.vault import encrypt_secret


@pytest_asyncio.fixture(autouse=True)
async def setup_db():
    await init_db()


def test_extract_candidate_domains():
    text = "Please check https://vercel.com/login and http://sub.github.com/settings or google.com but not script.py"
    domains = extract_candidate_domains(text)
    assert "vercel.com" in domains
    assert "sub.github.com" in domains
    assert "google.com" in domains
    assert "script.py" not in domains


def test_get_domain_slug():
    assert get_domain_slug("vercel.com") == "vercel"
    assert get_domain_slug("github.com") == "github"
    assert get_domain_slug("sub.domain.co.uk") == "domain"
    assert get_domain_slug("localhost") == "localhost"


@pytest.mark.asyncio
async def test_resolve_task_credentials_not_found():
    sens, allowed = await resolve_task_credentials(telegram_id=123456789, prompt="Check something")
    assert sens == {}
    assert allowed == []


@pytest.mark.asyncio
async def test_resolve_task_credentials_single_domain():
    telegram_id = 88776655
    async with async_session_factory() as session:
        user, _ = await UserRepository.get_or_create_by_telegram_id(session, telegram_id)
        pwd_blob = encrypt_secret("my_super_secret_password", settings.vault_key_bytes)
        totp_blob = encrypt_secret("JBSWY3DPEHPK3PXP", settings.vault_key_bytes)
        
        await CredentialRepository.add_or_update_credential(
            session,
            user_id=user.id,
            site_domain="vercel.com",
            auth_type="password",
            encrypted_blob=pwd_blob,
            username_or_identifier="testuser@example.com",
        )
        await CredentialRepository.add_or_update_credential(
            session,
            user_id=user.id,
            site_domain="vercel.com",
            auth_type="totp_seed",
            encrypted_blob=totp_blob,
        )
        await session.commit()

    # Match via prompt mentioning domain
    sens, allowed = await resolve_task_credentials(
        telegram_id=telegram_id,
        prompt="Please log into vercel.com and inspect dashboard",
    )
    sens = sens[credential_scope("vercel.com")]

    assert "vercel_user" in sens
    assert sens["vercel_user"] == "testuser@example.com"
    assert sens["vercel_pass"] == "my_super_secret_password"
    assert sens["vercel_bu_2fa_code"] == "JBSWY3DPEHPK3PXP"
    # Single-site convenience aliases
    assert sens["x_user"] == "testuser@example.com"
    assert sens["x_pass"] == "my_super_secret_password"

    assert "*.vercel.com" in allowed
    assert "vercel.com" in allowed


@pytest.mark.asyncio
async def test_resolve_task_credentials_slug_matching():
    telegram_id = 88776644
    async with async_session_factory() as session:
        user, _ = await UserRepository.get_or_create_by_telegram_id(session, telegram_id)
        pwd_blob = encrypt_secret("github_token_secret", settings.vault_key_bytes)
        
        await CredentialRepository.add_or_update_credential(
            session,
            user_id=user.id,
            site_domain="github.com",
            auth_type="password",
            encrypted_blob=pwd_blob,
            username_or_identifier="gh_dev",
        )
        await session.commit()

    # User says "github" without ".com"
    sens, allowed = await resolve_task_credentials(
        telegram_id=telegram_id,
        prompt="Login to github and star repository",
    )
    sens = sens[credential_scope("github.com")]

    assert sens["github_user"] == "gh_dev"
    assert sens["github_pass"] == "github_token_secret"
    assert "*.github.com" in allowed

