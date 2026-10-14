# Replace Dify's default passwords and keys without breaking anything

Use this after `dify_hardening_check.py` lists settings that "still have Dify's published default values". It covers a Docker Compose install from `dify/docker`. Run every command in that folder.

Most of these values can simply be changed in `docker/.env`. The exception is the **Postgres password**: Postgres stores the password it was created with in its data volume, so changing only `DB_PASSWORD` makes the API, worker and plugin daemon fail to connect. Change it inside the database first (step 3).

Made with AI agents for MV2 of Munim, Inc. Checked against Dify 1.17.1 on 14 October 2026. This is general technical information; test on a copy first if the server matters to you.

## 1. Back up

```sh
cd dify/docker
cp .env .env.backup-$(date +%Y%m%d)
docker compose ps        # note the service names; the database is db_postgres in current compose files
```

Back up the `volumes/` folder (or your named volumes) the way you normally do before an upgrade.

## 2. Make new values

Use hex values (`0-9a-f`). Base64 values contain `/` and `+`, which break `CELERY_BROKER_URL` because the Redis password sits inside that URL.

```sh
openssl rand -hex 32
```

Make one value per secret. Don't reuse one value for everything.

## 3. Postgres: change it in the database first

Find your database user (`DB_USERNAME` in `.env`, `postgres` by default), then run this, with your user in place of `postgres` in both spots if it differs:

```sh
docker compose exec db_postgres psql -U postgres -c '\password postgres'
```

`\password` asks for the new password twice and doesn't put it in your shell history. Then set the same value in `.env`:

```
DB_PASSWORD=<new value>
```

The plugin daemon connects to the same server with the same user (database `dify_plugin`), so this one change covers both.

If you use MySQL (`db_mysql`) instead, change the user's password there with `ALTER USER` first, the same way.

## 4. Redis: two places

Redis takes its password from the compose command line (`--requirepass ${REDIS_PASSWORD}`) at every start, so nothing inside Redis needs changing. But the password also sits inside the Celery broker URL:

```
REDIS_PASSWORD=<new value>
CELERY_BROKER_URL=redis://:<new value>@redis:6379/1
```

If you change only `REDIS_PASSWORD`, the worker can't reach its queue and workflows stop running.

## 5. Keys that come in pairs

Each pair must hold the same value. In `.env`:

| Set both | Used by |
|---|---|
| `SANDBOX_API_KEY` and `CODE_EXECUTION_API_KEY` | the code sandbox, and the API that calls it |
| `WEAVIATE_API_KEY` and `WEAVIATE_AUTHENTICATION_APIKEY_ALLOWED_KEYS` | Weaviate, and the API that queries it (only if `VECTOR_STORE=weaviate`) |

`PLUGIN_DAEMON_KEY` and `PLUGIN_DIFY_INNER_API_KEY` are each one setting in `.env` that both the API and the plugin daemon read, so change each once and recreate both containers (step 8 does that).

## 6. Dify Agent (1.17 and newer)

```
DIFY_AGENT_API_TOKEN=<new value>
DIFY_AGENT_SERVER_SECRET_KEY=<new value>
DIFY_AGENT_LOCAL_SANDBOX_AUTH_TOKEN=<new value>
```

Dify's example file says to replace the first two in production. `DIFY_AGENT_LOCAL_SANDBOX_AUTH_TOKEN` is empty by default, and the local sandbox's control API only asks for a token when one is set ([langgenius/dify#38609](https://github.com/langgenius/dify/issues/38609)). Before 1.17 it was called `DIFY_AGENT_SHELLCTL_AUTH_TOKEN`. Agent runs that are in progress when you restart may fail; start them again.

## 7. SECRET_KEY (only if the check flags it)

From 1.14.1 on, an empty `SECRET_KEY` is fine: Dify generates its own and keeps it. If the check says your key is the old public example key or a placeholder, set a new one:

```sh
openssl rand -base64 42
```

Everyone is signed out, signed file links stop working, and plugin OAuth credentials have to be set up again.

## 8. Apply and check

```sh
docker compose up -d                      # recreates the containers whose settings changed
docker compose ps                         # all services up and healthy
docker compose logs --tail 50 api worker plugin_daemon
python3 /path/to/dify_hardening_check.py .env docker-compose.yaml envs/*.env
```

Then sign in, run a workflow with a code node, and ask a question against a knowledge base. That exercises the database, Redis, the sandbox and the vector store.

If something fails to connect, compare the pair in step 4 or 5. To go back, restore `.env.backup-...`. If you already changed the Postgres password, set it back with `\password` too.

---

Want someone to go through this with you? MV2 of Munim, Inc. writes a [review of a shared Dify server](README.md#written-review) for $199.
