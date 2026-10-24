# Wilco

A self-hosted Telegram assistant that answers questions and carries out tasks in a browser. Wilco uses an external language model, runs Chromium locally or through Browserbase, and provides a Telegram Mini App called **Vault** for managing saved account details.

## What it does

- Routes natural-language messages to a direct answer, browser task, Vault, help, or cancellation.
- Runs browser tasks with progress tracking and screenshot evidence when available.
- Stores credentials and saved browser sessions encrypted with an AES-256-GCM master key.
- Requests missing credentials through a secure form and one-time codes through task-bound Telegram replies.
- Keeps conversation history in SQLite or PostgreSQL, separated by user and chat.
- Supports Gemini, OpenAI, and Anthropic model providers.

## Requirements

- Python 3.14 and [uv](https://docs.astral.sh/uv/getting-started/installation/).
- A Telegram bot token from [BotFather](https://t.me/BotFather).
- An API key and a supported model from your chosen LLM provider.
- Chromium for local browser tasks, or a Browserbase account.
- A public HTTPS address for Vault and for webhook mode. Local polling does not require an incoming webhook.

The model runs through an API; a GPU is not required on your machine.

## Quick start

### 1. Clone and install

```sh
git clone https://github.com/mossnotes/Wilco.git
cd Wilco
uv sync --locked
uv run playwright install chromium
```

On Linux, install Chromium's system dependencies as well:

```sh
uv run playwright install --with-deps chromium
```

`uv` uses the Python version in `.python-version`. The browser installation uses the Playwright version from this project's lockfile. See [Playwright's browser installation guide](https://playwright.dev/python/docs/browsers).

### 2. Configure the environment

Copy the example configuration:

```sh
# macOS / Linux
cp .env.example .env
```

```powershell
# Windows PowerShell
Copy-Item .env.example .env
```

Generate a vault key:

```sh
uv run python -c "import base64,secrets; print(base64.b64encode(secrets.token_bytes(32)).decode())"
```

Edit `.env` and set at least:

```dotenv
TELEGRAM_BOT_TOKEN=<your BotFather token>
VAULT_MASTER_KEY=<the generated key>
BOT_MODE=polling
LLM_PROVIDER=gemini
LLM_MODEL=gemini-3.8-flash
GEMINI_API_KEY=<your provider API key>
```

For another provider, change `LLM_PROVIDER`, choose a model available to your account, and set `OPENAI_API_KEY` or `ANTHROPIC_API_KEY`. `GOOGLE_API_KEY` is accepted as a fallback for `GEMINI_API_KEY`. Only the selected provider's key is required.

Keep the vault key stable and back it up securely. A new key cannot decrypt credentials or browser profiles encrypted with the previous key.

### 3. Run

```sh
uv run python main.py
```

The server listens on `http://localhost:8000` by default:

- `/health`: process liveness and basic configuration.
- `/docs`: FastAPI's API documentation.
- `/companion/accounts`: Vault, opened and authenticated through Telegram.

Message your bot privately. For example:

- "What can you do?"
- "Find the latest Python release."
- "Open my Vault."
- "Stop the current task."

### 4. Enable Vault

Expose local port 8000 through an HTTPS tunnel, or use your deployed HTTPS domain, then set:

```dotenv
COMPANION_BASE_URL=https://your-domain.example/companion
```

Restart Wilco and ask the bot to open Vault. Use the button inside Telegram so the Mini App can supply the signed Telegram identity. A plain browser tab does not provide that identity.

Polling and Vault are independent: polling can remain enabled while Vault uses your public HTTPS address.

## Configuration

[`app/config.py`](app/config.py) defines every setting and default. [`.env.example`](.env.example) contains the usual overrides. System environment variables take precedence over `.env`.

| Setting | Default / purpose |
| --- | --- |
| `DATABASE_URL` | `sqlite+aiosqlite:///./wilco.db` |
| `BOT_MODE` | The example uses `polling`; the application default is `webhook`. |
| `COMPANION_BASE_URL` | Public address ending in `/companion` for Vault. |
| `BROWSER_TYPE` | `local` or `browserbase`. |
| `BROWSER_HEADLESS` | `true`; set `false` to show the local browser window. |
| `TASK_TIMEOUT_SECONDS` | `300`, including time spent waiting for browser-task input. |
| `ROUTING_TIMEOUT_SECONDS` | `60`, for the initial model decision. |
| `CONVERSATION_MEMORY_ENABLED` | `true`; stores sanitized conversation context in the database. |
| `LOG_LEVEL` | `INFO`; `DEBUG` also logs redacted Gemini request/response payloads. |
| `TELEGRAM_DEBUG_STATUS` | `false`; enables internal browser progress cards when debugging. |
| `HOST` / `PORT` | `0.0.0.0` / `8000`. |

For Browserbase, set `BROWSER_TYPE=browserbase`, `BROWSERBASE_API_KEY`, and `BROWSERBASE_PROJECT_ID`. Local Chromium is not required for that mode.

## Deploying on a Google Cloud VM

The current architecture suits one continuously running Compute Engine VM with **one application process**. An `e2-standard-2` VM (2 vCPUs, 8 GB RAM) is a reasonable pilot starting point; measure representative browser tasks before increasing concurrency. No Docker image or automated cloud deployment is included yet.

For webhook mode, configure:

```dotenv
BOT_MODE=webhook
TELEGRAM_WEBHOOK_URL=https://your-domain.example
TELEGRAM_WEBHOOK_SECRET=<a random secret>
COMPANION_BASE_URL=https://your-domain.example/companion
```

Wilco appends `WEBHOOK_PATH` (default `/webhook/telegram`) and registers the webhook on startup. Put an HTTPS reverse proxy in front of port 8000. Use a different bot token for staging; one bot has one active webhook destination.

SQLite is suitable for an initial single-VM deployment. Store the database on persistent disk outside release directories or disposable container filesystems. If a container mounts that directory at `/data`, use:

```dotenv
DATABASE_URL=sqlite+aiosqlite:////data/wilco.db
```

Back up the database consistently with [SQLite's backup API](https://www.sqlite.org/backup.html), and keep the vault key separately in secure storage. Deployments must preserve both data and key. WAL mode and a busy timeout are not configured by this project yet.

PostgreSQL is available through `postgresql+asyncpg://user:password@host:5432/wilco`. Moving an existing SQLite installation requires transferring its data; changing the URL alone creates or opens a different database.

## Development and CI

```sh
uv sync --locked
uv run pytest -q
```

Tests mock external model, Telegram, and browser calls and do not require provider credentials or an installed browser. See [CONTRIBUTING.md](CONTRIBUTING.md) for development guidance.

[GitHub Actions](.github/workflows/ci.yml) installs the locked dependencies and runs the tests on Linux and Windows for pushes and pull requests. It does not deploy anything. A later deployment workflow can build a container, publish it to Artifact Registry, and update the VM only after CI succeeds.

## Current limits

- Active browser tasks, input requests, and coordination locks are held in memory. Restarts interrupt active work; there is no durable job queue or automatic task recovery.
- One browser task is permitted per chat. There is no enforced global browser cap or queue, and the per-chat rule is not a per-user limit across group chats.
- Use one application process. Multiple replicas require shared coordination in addition to a shared database.
- Tables are created on startup, but versioned schema migrations are not implemented.
- `/health` is a liveness check, not a database readiness check. Startup currently logs database or Telegram initialization failures and can continue serving HTTP.
- Startup currently discards pending Telegram updates when registering a webhook or switching to polling. Release draining and preserving queued updates remain deployment work.
- There is no deployment-wide Telegram user allowlist. Anyone able to message the bot can use its assistant capabilities; each user's Vault data is authenticated separately.

Keep secrets in `.env` or your hosting secret store. Debug logs can contain conversation content even when credentials are redacted. Browser actions can change real accounts; cancellation stops further execution and does not undo completed website actions.

## Project layout

```text
app/api/          Health and Telegram webhook endpoints
app/bot/          Routing, message delivery, tools, and conversation memory
app/browser/      Browser lifecycle, agent, credential resolution, and execution
app/companion/    Vault routes, templates, and static assets
app/db/           SQLAlchemy models, sessions, and repositories
app/security/     Encryption, input validation, origins, and browser access
app/tasks/        Task state and in-memory coordination
tests/            Unit and integration tests with mocked external services
main.py           Application entry point
```

## License

Wilco is licensed under the [MIT License](LICENSE). The bundled Gowun Batang font retains its [SIL Open Font License](app/companion/static/fonts/OFL.txt).
