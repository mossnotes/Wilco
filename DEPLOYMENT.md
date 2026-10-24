# Single-VM Docker deployment

This configuration runs one Wilco process with local Chromium and SQLite on a persistent Docker volume. It is intended for an initial deployment on an 8 GB Linux VM. The container has a 6 GB memory ceiling; this is not a browser concurrency limit.

## Files

- `Dockerfile`: Python 3.14, locked runtime dependencies, Chromium and its system dependencies, and a non-root application user.
- `.dockerignore`: limits the build context to runtime code and metadata. Local secrets, databases, tests, and Git history are excluded.
- `compose.yaml`: runtime secrets from `.env`, persistent SQLite storage, process restart, shared memory for Chromium, and bounded log files.

## Configuration

Copy `.env.example` to `.env` on the VM and configure the Telegram bot token, a stable vault master key, and the selected model provider's API key. Keep `.env` private and outside Git. Reuse the original vault key if moving existing encrypted account data.

For the first local check, keep `BOT_MODE=polling`. Once a public HTTPS address is ready, set `COMPANION_BASE_URL` to `https://your-hostname/companion`. Webhook mode additionally requires `BOT_MODE=webhook`, `TELEGRAM_WEBHOOK_URL=https://your-hostname`, and a random `TELEGRAM_WEBHOOK_SECRET`.

Compose overrides `DATABASE_URL` with `sqlite+aiosqlite:////data/wilco.db`, regardless of the value in `.env`. The named volume stores the database, saved account details, conversation history, and encrypted browser profiles. An existing host-side `wilco.db` is not imported automatically. PostgreSQL deployments must change the Compose database setting and migrate existing data explicitly.

## Build and run

Run these commands from the repository directory after configuring `.env`:

```sh
sudo docker compose config --quiet
sudo docker compose up -d --build
```

The first build downloads Python dependencies, Chromium, and Linux libraries. No host-side Python installation is needed. The application runs as the `wilco` container user, with one process and no development reload.

Verify HTTP from the VM:

```sh
curl --fail http://127.0.0.1:8000/health
```

`/health` reports process liveness and basic configuration. It does not prove that the database, model API, or Telegram integration works; complete a real bot task before considering the deployment ready.

## Public HTTPS

The application port is published only at `127.0.0.1:8000` on the VM. Configure a host-side HTTPS reverse proxy such as Caddy, pointing to that address, and allow inbound TCP ports 80 and 443 in the Google Cloud firewall. Port 8000 should remain private.

A free DuckDNS hostname can point to the VM's external IP address. Keep that DNS record current if the VM's IP changes. Caddy can provision and renew a certificate for the hostname. The Mini App must be opened through Telegram for authenticated Mini App identity.

HTTPS and DNS are configured separately from this Compose file. Do not expose the raw application port as a substitute for HTTPS.

## Updates and data

Wait for active tasks to finish before replacing the application container. After fetching a reviewed release, rebuild and replace it with:

```sh
sudo docker compose up -d --build
```

Normal container replacement preserves `wilco_data`. `docker compose down` also preserves it; adding `--volumes` deletes the named volume and its data. Back up SQLite consistently with its backup API, and keep a separate secure backup of `VAULT_MASTER_KEY`.

## CI and known limits

GitHub Actions runs the existing test suite, builds the Docker image, and checks HTTP startup plus headless Chromium startup. Those checks use no real Telegram or model credentials. CI does not deploy the VM automatically.

Active tasks and pending input live in memory, so restarts interrupt them. There is no durable queue or enforced global browser cap, and startup currently discards pending Telegram updates. Do not scale this service to multiple processes or replicas without shared task coordination. The Docker memory limit protects the VM from unlimited container memory growth; reaching it can terminate work.
