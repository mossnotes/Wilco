# syntax=docker/dockerfile:1
FROM python:3.14-slim-trixie

COPY --from=ghcr.io/astral-sh/uv:0.11.19 /uv /usr/local/bin/uv

ENV PYTHONUNBUFFERED=1 \
    PYTHONDONTWRITEBYTECODE=1 \
    UV_PYTHON_DOWNLOADS=never \
    UV_LINK_MODE=copy \
    PLAYWRIGHT_BROWSERS_PATH=/opt/chromium \
    ANONYMIZED_TELEMETRY=false \
    PATH="/app/.venv/bin:$PATH"

WORKDIR /app

COPY pyproject.toml uv.lock README.md LICENSE ./

# Install the locked runtime dependencies and matching Chromium binaries.
RUN --mount=type=cache,target=/root/.cache/uv \
    uv sync --locked --no-dev --no-install-project \
    && uv run --no-sync playwright install --with-deps chromium \
    && rm -rf /var/lib/apt/lists/*

RUN groupadd --gid 10001 wilco \
    && useradd --uid 10001 --gid wilco --create-home --shell /usr/sbin/nologin wilco \
    && mkdir -p /data \
    && chown wilco:wilco /app /data

COPY --chown=wilco:wilco app ./app
COPY --chown=wilco:wilco main.py ./

USER wilco
ENV HOME=/home/wilco

EXPOSE 8000

# This is a process liveness check; it does not validate Telegram or the database.
HEALTHCHECK --interval=30s --timeout=5s --start-period=60s --retries=3 \
    CMD ["python", "-c", "import urllib.request; urllib.request.urlopen('http://127.0.0.1:8000/health', timeout=3).close()"]

CMD ["python", "main.py"]
