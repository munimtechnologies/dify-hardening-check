# dify-hardening-check

Check a self-hosted [Dify](https://github.com/langgenius/dify) deployment, in one command, for:
- the default passwords and keys Dify ships with,
- databases and sandboxes published to the network,
- risky settings,
- Dify's known security advisories.

- Reads `docker/.env`, `docker/docker-compose.yaml`, the `docker/envs/*.env` files, `docker inspect` output or a Kubernetes manifest. It can also check the address of a server you run.
- Runs as a GitHub Action, so a pull request that brings a default password back fails before it ships.
- One Python file, standard library only, read-only. **Secret values are never printed.** It reports only the *names* of settings that still hold a published default, such as `DB_PASSWORD`.

Made with AI agents for MV2 of Munim, Inc. Defaults and advisory data were checked on 14 October 2026 against Dify 1.17.1.

**Found defaults? [ROTATE.md](ROTATE.md) shows how to replace each one without breaking Postgres, Redis or the plugin daemon.**

## Why

Dify's example env file is public, and so is every value in it: `difyai123456` for Postgres and Redis, `dify-sandbox` for the code sandbox, the plugin daemon keys and the Dify Agent tokens. Before 1.14.1 it also held a fixed `SECRET_KEY`, which signs every sign-in token. Since 1.17 it also leaves the Dify Agent local sandbox's access token empty.

Most guides say "change the defaults". This tool tells you which ones you haven't changed. It also flags the ports that make them dangerous. One example is `docker-compose.middleware.yaml`, which publishes Postgres, Redis, the sandbox proxy, the agent's local sandbox and Weaviate on every network interface.

## Quick start

```sh
curl -O https://raw.githubusercontent.com/munimv2/dify-hardening-check/main/dify_hardening_check.py

cd dify/docker
python3 /path/to/dify_hardening_check.py .env docker-compose.yaml envs/*.env
python3 /path/to/dify_hardening_check.py --url https://dify.example.com
docker inspect $(docker ps -q) > inspect.json && python3 dify_hardening_check.py inspect.json
```

Options:

| Option | What it does |
|---|---|
| `--url URL` | Checks a server you run, the way any visitor sees it (see below). |
| `--json` / `--markdown` | Prints the report as JSON or Markdown instead of text. |
| `--fail-on high` | Sets the exit code: 1 when a finding is this severe or worse. Choices: `critical`, `high` (the default), `medium`, `low`, `never`. Use it in CI. |

Example output (shortened):

```
Dify hardening check 0.1.2
Checked: docker-compose.middleware.yaml, .env
Dify version: unknown

CRITICAL  PostgreSQL is published on every network interface (host port 5432) with a published default credential
          DB_PASSWORD is still Dify's published default, so anyone who can reach the port can use it.
          This is the setup CVE-2025-56157 (CVSS 9.8) describes.
          Fix: Remove the port mapping, or publish it as "127.0.0.1:5432:5432". ...
CRITICAL  The Dify Agent local sandbox is published on every network interface (host port 5004) without an access token
CRITICAL  The code sandbox (through the SSRF proxy) is published on every network interface (host port 8194) ...
MEDIUM    8 passwords and keys still have Dify's published default values
          Settings: CELERY_BROKER_URL, CODE_EXECUTION_API_KEY, DB_PASSWORD, DIFY_AGENT_API_TOKEN, ...
MEDIUM    Dify Agent's local sandbox has no access token (DIFY_AGENT_LOCAL_SANDBOX_AUTH_TOKEN is empty, the default)
MEDIUM    The console API accepts requests from every origin (CONSOLE_CORS_ALLOW_ORIGINS=*, the default)
LOW       No init password (INIT_PASSWORD is empty)
...
```

## CVE-2025-56157: am I affected?

[CVE-2025-56157](https://nvd.nist.gov/vuln/detail/CVE-2025-56157) (CVSS 9.8, published 18 December 2025) is about the PostgreSQL username and password in Dify's `docker/docker-compose.yaml`: anyone who can reach port 5432 can sign in to the database with the published password. The record lists Dify "through 1.5.1". Dify notes that its Docker setup doesn't publish 5432 by default since 1.0.1.

Scanners often show this CVE with **no fixed version**, because updating doesn't help: Dify 1.17.1's example env file still ships the same `DB_PASSWORD`, and Postgres keeps the password it was created with. What matters is your setup:

| Your setup | Risk | What the tool reports |
|---|---|---|
| `DB_PASSWORD` is still the published default **and** 5432 is published on every interface (for example by `docker-compose.middleware.yaml`, or a `ports:` line you added) | The CVE applies as written | critical, naming CVE-2025-56157 |
| `DB_PASSWORD` is still the default, 5432 isn't published | Only containers and plugins inside the Docker network can use it | medium, naming CVE-2025-56157 |
| You changed the password, 5432 is still published | Exposed, but not with a known password | high: bind it to `127.0.0.1` |
| You changed the password, 5432 isn't published | Not affected | nothing |

Check it:

```sh
cd dify/docker
python3 /path/to/dify_hardening_check.py .env docker-compose.yaml docker-compose.middleware.yaml
```

To fix it, follow [ROTATE.md](ROTATE.md). Change the password inside Postgres first (`\password` through `docker compose exec`), then in `DB_PASSWORD`, then restart. If you publish 5432, bind it to `127.0.0.1:5432:5432`.

## In CI (GitHub Actions)

If your Dify deployment files (an `.env` template, compose overrides, Kubernetes manifests) live in a repository, check them on every push and pull request:

```yaml
# .github/workflows/dify-hardening.yml
name: Dify hardening
on: [push, pull_request]
jobs:
  check:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v4
      - uses: munimv2/dify-hardening-check@v0.1.2
        with:
          files: docker/.env docker/docker-compose.yaml docker/envs/*.env   # spaces or new lines; wildcards work
          fail-on: high                                                      # critical, high, medium, low or never
```

- The report goes to the job log and the job summary. Critical and high findings become error annotations, medium ones warnings.
- The step fails when a finding is at least as severe as `fail-on`.
- Outputs: `report` (path of the JSON report) and the counts `critical`, `high`, `medium` and `low`.
- Files that don't exist are skipped with a warning.
- `url` also works. Only use it for a server you run, and keep in mind that the job summary shows the address.

It needs Python 3, which GitHub's Linux and macOS runners have. Pin a release tag (`@v0.1.2`) and update on purpose.

## What it checks

From your files:

| Area | Checks |
|---|---|
| Secret key | `SECRET_KEY` is the public key from the old example file, a placeholder, or shorter than 32 characters. It also flags an empty key on versions before 1.14.1, whose compose file filled it with the public key. |
| Published defaults | `DB_PASSWORD` (CVE-2025-56157), `REDIS_PASSWORD` (also inside `CELERY_BROKER_URL`), `SANDBOX_API_KEY` / `CODE_EXECUTION_API_KEY`, `PLUGIN_DAEMON_KEY`, `PLUGIN_DIFY_INNER_API_KEY`, `DIFY_AGENT_API_TOKEN`, `DIFY_AGENT_SERVER_SECRET_KEY`, plus the credentials of the vector store selected in `VECTOR_STORE`. Placeholders for services you don't use are listed separately as info. |
| Agent sandbox | An empty `DIFY_AGENT_LOCAL_SANDBOX_AUTH_TOKEN` (the 1.17 default) while the local sandbox backend is used. The sandbox's control API only asks for a token when one is set ([langgenius/dify#38609](https://github.com/langgenius/dify/issues/38609)). It also notes a value left under the pre-1.17 name `DIFY_AGENT_SHELLCTL_AUTH_TOKEN`. |
| Ports | Postgres, MySQL, Redis, the sandbox proxy, the plugin daemon, the agent's local sandbox and vector databases published on every interface. It's critical when the service's credential is still the default, or for the local sandbox when it has no token. The plugin remote-debugging port 5003, which the stock compose file publishes, is flagged as low. |
| Setup | Empty `INIT_PASSWORD`: until setup is finished, anyone who opens `/install` can create the owner account. |
| Network and web | `CONSOLE_CORS_ALLOW_ORIGINS=*` and `WEB_API_CORS_ALLOW_ORIGINS=*`; plain `http://` addresses in `CONSOLE_WEB_URL`, `APP_WEB_URL` and the like; `NGINX_HTTPS_ENABLED=false`; an empty `SSRF_PROXY_HTTP_URL`; `ALLOW_UNSAFE_DATA_SCHEME`; `ALLOW_EMBED` |
| Plugins and debugging | `FORCE_VERIFYING_SIGNATURE=false`; `DEBUG`, `FLASK_DEBUG`, `DEPLOY_ENV=DEVELOPMENT`, `ENABLE_REQUEST_LOGGING` |
| Version | Every advisory in [`ADVISORIES`](dify_hardening_check.py) is matched against the `langgenius/dify-api` / `dify-web` image tag. Upgrading to 1.16.0 or newer fixes all of them, and the latest release is safest. Tags such as `:latest` that move are flagged. |

With `--url`, it reads only what any visitor's browser loads before signing in:
- `/console/api/setup` and `/console/api/init`, which the console uses to decide whether to show `/install`. If setup isn't finished and no init password is set, **the next visitor creates the owner account**.
- The console API's CORS answer to a request from a made-up origin.
- Whether the address uses plain HTTP.
- The security headers on the start page.

It never signs in, sends a password or changes anything. Only run it against servers you run.

## Limits

- **Settings are read as one flat list.** If two services in a compose file use the same variable name, the last one read wins. `docker/.env` wins over `docker/envs/*.env`, as in Dify.
- **Some values can't be read.** Values that come from elsewhere (`${VAR}` without a value in your files, Kubernetes `valueFrom`, `$(command)`) are treated as unknown and not judged. The agent sandbox check needs `docker/.env` (or the sandbox container's `docker inspect`) to say whether a token is set.
- **Not a scanner or a certification.** This is general technical information. It doesn't scan networks or test for vulnerabilities.

If a default, a range or an advisory is wrong or out of date, please [open an issue](https://github.com/munimv2/dify-hardening-check/issues).

## Written review

MV2 of Munim, Inc. also writes a review of a self-hosted AI setup. It covers what's exposed, risky or out of date, and what to fix first, with exact commands for your OS, plus one follow-up check by email. The review is made with AI agents and is general technical information. See a [sample report](https://munimv2.github.io/sample-report.html).

- **$199, small office:** one shared server such as Dify, Open WebUI, Ollama or n8n used by a team, or up to 5 machines. [Pay on Stripe](https://buy.stripe.com/aFabJ0foU2vw6Jo8o13Ru01).
- **$49, one machine:** [pay on Stripe](https://buy.stripe.com/5kQcN43Gcfii6Jo47L3Ru00).

After paying, email munimversion2@gmail.com:
- the `--json` output of this tool (remove the URL if you prefer),
- your Dify version and OS,
- what the server is used for.

The review arrives within 48 hours of receiving everything. MV2 never asks for passwords, keys or remote access, and this tool never prints them.

Also by MV2: [openwebui-hardening-check](https://github.com/munimv2/openwebui-hardening-check), the same kind of check for Open WebUI.

## Development

```sh
python3 -m unittest test_dify_hardening_check.py test_action.py
```

Apache-2.0 licensed. Sources:
- Dify's [environment variable docs](https://docs.dify.ai/en/self-host/deploy/configuration/environments)
- the [`docker/.env.example`](https://github.com/langgenius/dify/blob/main/docker/.env.example) and compose files
- [Dify's security advisories](https://github.com/langgenius/dify/security/advisories)
- [CVE-2025-56157](https://nvd.nist.gov/vuln/detail/CVE-2025-56157) on the published PostgreSQL password
- [langgenius/dify#38609](https://github.com/langgenius/dify/issues/38609) on the local sandbox's optional token

Dify is a trademark of LangGenius, Inc. This project isn't affiliated with or endorsed by LangGenius.
