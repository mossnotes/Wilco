from app.security.sanitizer import (
    REDACTED_LABEL,
    contains_sensitive_data,
    sanitize_log,
)


def test_contains_sensitive_data_detection():
    # API Keys
    assert contains_sensitive_data("sk-ant-api03-abcdef1234567890abcdef1234567890")
    assert contains_sensitive_data("Bearer eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.abcdef")
    assert contains_sensitive_data("ghp_1234567890abcdefghijklmnopqrstuvwxyz1234")

    # Telegram bot token
    assert contains_sensitive_data("123456789:ABCdefGHIjklMNOpqrSTUvwxYZ123456789")

    # Passwords
    assert contains_sensitive_data("password: SuperSecretPass123!")
    assert contains_sensitive_data("pwd=mySecretValue99")
    assert contains_sensitive_data("my password is HighlyConfidential123")

    # Base32 TOTP Seed
    assert contains_sensitive_data("Use seed JBSWY3DPEHPK3PXP for login")


def test_benign_text_no_false_positives():
    benign_messages = [
        "Please navigate to https://news.ycombinator.com and extract top stories.",
        "Check weather in Tokyo and take a screenshot.",
        "What is the status of the server?",
        "Order 2 books from Amazon.",
        "Hello Wilco bot!",
    ]

    for msg in benign_messages:
        assert not contains_sensitive_data(msg), f"False positive on: {msg}"


def test_sanitize_log():
    # Passwords in log
    log_line = "Failed to connect with password: MySecretPassword123! to database"
    sanitized = sanitize_log(log_line)
    assert "MySecretPassword123!" not in sanitized
    assert f"password: {REDACTED_LABEL}" in sanitized

    # API key in log
    api_log = "Using API key sk-ant-api03-abcdef1234567890abcdef1234567890 for request"
    sanitized_api = sanitize_log(api_log)
    assert "sk-ant-api03" not in sanitized_api
    assert REDACTED_LABEL in sanitized_api

    # Telegram message chat pattern
    chat_msg = "Hey, my password is SecretPassword123! please help"
    sanitized_chat = sanitize_log(chat_msg)
    assert "SecretPassword123!" not in sanitized_chat
    assert REDACTED_LABEL in sanitized_chat

