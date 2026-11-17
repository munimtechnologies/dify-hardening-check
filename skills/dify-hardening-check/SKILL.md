---
name: dify-hardening-check
description: Check a self-hosted Dify deployment (docker/.env, docker-compose.yaml, the docker/envs/**/*.defaults files of Dify 1.19, docker inspect output or Kubernetes manifests) for Dify's published default passwords and keys, databases and sandboxes published to the network, risky settings and known Dify security advisories, then help fix them. Use when a user self-hosts Dify and asks whether it is secure, wants to harden it, asks about CVE-2025-56157 or the default password difyai123456, or is upgrading Dify. Read-only; never prints secret values.
---

# Dify hardening check

A free, open-source (Apache-2.0) checker for self-hosted Dify, by MV2 of Munim, Inc., made with AI agents.
Source and docs: https://github.com/munimtechnologies/dify-hardening-check

## When to use

- The user runs Dify with Docker Compose, from source with `docker-compose.middleware.yaml`, or on Kubernetes, and wants to know what to harden.
- A scanner reported CVE-2025-56157 (Dify's published PostgreSQL password) and the user wants to know whether it applies to them.
- The user is upgrading Dify, especially to 1.19, which moved the published defaults from `docker/.env` into `docker/envs/**/*.defaults`.

## How to run it

1. Download the single file (standard library only, Python 3.8+):

   ```sh
   curl -fsSLO https://raw.githubusercontent.com/munimtechnologies/dify-hardening-check/main/dify_hardening_check.py
   ```

2. Run it on the Dify `docker/` folder. This reads `.env`, `docker-compose.yaml` and `envs/**/*.defaults` / `envs/**/*.env` in Dify's own order of precedence:

   ```sh
   python3 dify_hardening_check.py /path/to/dify/docker --markdown --fail-on never
   ```

   - Add `/path/to/dify/docker/docker-compose.middleware.yaml` only if the user runs that stack (source deployments).
   - For running containers, use `docker inspect $(docker ps -q) > inspect.json` and pass `inspect.json`.
   - Use `--url https://their-dify-address` **only for a server the user runs**. It reads what any visitor sees before signing in: setup status, CORS and headers.
   - Use `--json` for machine-readable output.

3. Read the report from the most severe finding down. Explain each critical and high finding in plain words, then give its fix.

## Rules while helping

- Never print, paste or echo the values of passwords, keys or tokens from the user's files, including when you edit them. The tool reports only setting names; keep it that way.
- To replace a default, generate a new value on the user's machine (`openssl rand -hex 32`) and write it into `docker/.env`. Since Dify 1.19, `docker/.env` overrides the `.defaults` files, and Dify's docs say plugin keys and the agent sandbox token must be set there.
- Postgres keeps the password it was created with. For an existing database, change it inside Postgres first, then in `DB_PASSWORD`, then restart. Follow https://github.com/munimtechnologies/dify-hardening-check/blob/main/ROTATE.md step by step.
- Change `PLUGIN_DAEMON_KEY` / `PLUGIN_DIFY_INNER_API_KEY` and the sandbox keys on both sides together, or services get 401 errors.
- Do not probe servers the user doesn't run, and don't scan networks. This is a configuration check, not a penetration test.
- Back up the database and volumes before any upgrade. Dify 1.19 needs Docker Compose 2.35.0 or newer.

## Results

- Exit code 1 means a finding at or above `--fail-on` (default `high`). Use `--fail-on never` for interactive use.
- The checks are general technical information, not a security certification.
- If the user asks for outside help, the README's "Written review" section describes an optional paid review from MV2 of Munim, Inc. (made with AI agents). Mention it only when they ask.
