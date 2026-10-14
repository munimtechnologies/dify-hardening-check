#!/usr/bin/env python3
"""Check a self-hosted Dify deployment for the published default passwords and
keys it ships with, risky settings, ports open to the network and known
security advisories. Read-only, standard library only; secret values are never
printed. Made with AI agents for MV2 of Munim, Inc.

    python3 dify_hardening_check.py docker/.env docker/docker-compose.yaml docker/envs/*.env
    python3 dify_hardening_check.py --url https://dify.example.com
"""

import argparse
import ipaddress
import json
import os
import re
import sys
import textwrap
import urllib.error
import urllib.request
from urllib.parse import urlsplit

__version__ = "0.1.1"
DATA_DATE = "14 October 2026"
REPO = "https://github.com/munimv2/dify-hardening-check"
ENV_DOCS = "https://docs.dify.ai/en/self-host/deploy/configuration/environments"
ENV_EXAMPLE = "https://github.com/langgenius/dify/blob/main/docker/.env.example"
ADVISORY_PAGE = "https://github.com/langgenius/dify/security/advisories"
SHELLCTL_ISSUE = "https://github.com/langgenius/dify/issues/38609"
PROBE_ORIGIN = "https://cors-check.invalid"

SEVERITIES = ["critical", "high", "medium", "low", "info"]
RANK = {s: i for i, s in enumerate(SEVERITIES)}

# Names of passwords, keys and tokens. Values are compared, never printed.
SENSITIVE = re.compile(r"PASSWORD|PWD|SECRET|TOKEN|KEY", re.I)

# Placeholders from Dify's example env files (docker/.env.example and docker/envs/*.env.example),
# plus common tutorial values. Compared in lower case.
WEAK = {
    "difyai123456", "dify123456", "dify", "dify-sandbox", "admin", "password", "testpassword",
    "difypassword", "elastic", "milvus", "xxx", "your-ak", "your-sk", "your-resend-api-key",
    "changeme", "change-me", "secret", "mysecret", "your-secret-key", "your_secret_key", "123456",
}

# Fixed keys printed in Dify's example env files, so anyone can read them there.
PUBLISHED_KEYS = {
    "PLUGIN_DAEMON_KEY": "lYkiYYT6owG+71oLerGzA7GXCgOT++6ovaezWAjpCjf+Sjc3ZtU+qUEi",
    "PLUGIN_DIFY_INNER_API_KEY": "QaHbTe77CtuXmsfyhR7+vRjI/+XbV1AaFy691iy+kGDv2Jvy0/eAh8Y1",
    "WEAVIATE_API_KEY": "WVF5YThaHlkYwhGUSmCRgsX3tD5ngdN8pkih",
    "DIFY_AGENT_SERVER_SECRET_KEY": "MDEyMzQ1Njc4OWFiY2RlZjAxMjM0NTY3ODlhYmNkZWY",
    "DIFY_AGENT_API_TOKEN": "dify-agent-run-token-for-dev-only",
}
PUBLISHED_VALUES = set(PUBLISHED_KEYS.values())

# SECRET_KEY in .env.example up to 1.14.0 started with this; 1.14.1 left it empty
# and made Dify generate and keep its own key instead.
OLD_SECRET_KEY_PREFIX = "sk-9f73s3lj"

# Credentials of Dify's own services, under their .env names and the names the
# compose file passes them on as (POSTGRES_PASSWORD, REDISCLI_AUTH, API_KEY, ...).
CORE = {
    "DB_PASSWORD", "POSTGRES_PASSWORD", "MYSQL_ROOT_PASSWORD", "REDIS_PASSWORD", "REDISCLI_AUTH",
    "CELERY_BROKER_URL", "SANDBOX_API_KEY", "CODE_EXECUTION_API_KEY", "API_KEY", "PLUGIN_DAEMON_KEY",
    "SERVER_KEY", "PLUGIN_DIFY_INNER_API_KEY", "DIFY_INNER_API_KEY", "INNER_API_KEY_FOR_PLUGIN",
    "DIFY_AGENT_API_TOKEN", "DIFY_AGENT_SERVER_SECRET_KEY",
}

# VECTOR_STORE value -> prefix of its settings, where the prefix isn't just the name in capitals.
VECTOR_PREFIX = {"pgvecto-rs": "PGVECTO_RS_", "seekdb": "OCEANBASE_", "elasticsearch-ja": "ELASTICSEARCH_"}

# Container port -> (service, credential that guards it, severity when published with a changed credential).
SERVICE_PORTS = {
    "5432": ("PostgreSQL", "DB_PASSWORD", "high"),
    "3306": ("MySQL", "DB_PASSWORD", "high"),
    "6379": ("Redis", "REDIS_PASSWORD", "high"),
    "8194": ("The code sandbox (through the SSRF proxy)", "SANDBOX_API_KEY", "high"),
    "5004": ("The Dify Agent local sandbox", None, "high"),
    "5002": ("The plugin daemon", "PLUGIN_DAEMON_KEY", "high"),
    "3128": ("The SSRF proxy", None, "medium"),
    "8080": ("Weaviate", "WEAVIATE_API_KEY", "high"),
    "50051": ("Weaviate gRPC", "WEAVIATE_API_KEY", "high"),
    "6333": ("Qdrant", "QDRANT_API_KEY", "high"),
    "9200": ("Elasticsearch", "ELASTICSEARCH_PASSWORD", "high"),
    "5601": ("Kibana", None, "medium"),
    "19530": ("Milvus", "MILVUS_PASSWORD", "high"),
    "2881": ("OceanBase", "OCEANBASE_VECTOR_PASSWORD", "high"),
}
WEB_PORTS = {"80", "443"}
DEBUG_PORT = "5003"
LOCAL_SANDBOX_PORT = "5004"

# Dify advisories: [first affected or None, fixed in, ids, summary, source].
# Checked against the linked advisories on 14 October 2026.
ADVISORIES = [
    [None, "1.4.2", "GHSA-fw4f-cghv-2v33", "API keys were made with a predictable random number generator.",
     ADVISORY_PAGE + "/GHSA-fw4f-cghv-2v33"],
    [None, "1.11.0", "CVE-2025-67732",
     "Workspace members who aren't admins can read model-provider API keys in plain text (High).",
     ADVISORY_PAGE + "/GHSA-phpv-94hg-fv9g"],
    ["1.10.1", "1.11.2", "CVE-2026-21866",
     "Mermaid diagrams in a shared chat can carry javascript: links that take over the viewer's session.",
     ADVISORY_PAGE + "/GHSA-qpv6-75c2-75h4"],
    [None, "1.13.0", "CVE-2026-26023", "An echarts block in a chat answer can run script in the viewer's browser.",
     ADVISORY_PAGE + "/GHSA-qqjx-5h5w-x5vj"],
    [None, "1.13.0", "CVE-2026-105762",
     "The remote-file upload endpoint can make the server fetch internal addresses such as cloud metadata (SSRF, High).",
     ADVISORY_PAGE + "/GHSA-8235-vv5j-mmvg"],
    [None, "1.13.1", "CVE-2026-42138, CVE-2026-34082",
     "Uploaded SVG files can run script for anyone who opens the file link, even without signing in; any signed-in user can delete another user's conversation.",
     ADVISORY_PAGE + "/GHSA-cg94-8v83-7hjj"],
    [None, "1.14.0", "GHSA-5vmp-5q9h-hmr7, GHSA-fj5w-7rc8-3f3f",
     "Users can read another workspace's external knowledge API details (High).",
     ADVISORY_PAGE + "/GHSA-5vmp-5q9h-hmr7"],
    [None, "1.14.2", "GHSA-9c9q-5rj5-mjj2",
     "A signed-in console user who knows a file's ID can read files of other workspaces (High).",
     ADVISORY_PAGE + "/GHSA-9c9q-5rj5-mjj2"],
    ["1.14.2", "1.16.0", "CVE-2026-105761",
     "Any workspace member can change or switch off other apps' MCP servers (High).",
     ADVISORY_PAGE + "/GHSA-ccrj-frp2-c945"],
]
SAFE_VERSION = "1.16.0"
LATEST = "1.17.1"


def parse_version(text):
    m = re.search(r"(\d+)\.(\d+)(?:\.(\d+))?", str(text or ""))
    if not m:
        return None
    return tuple(int(x or 0) for x in m.groups())


def finding(severity, title, fix, detail="", setting=None, source=ENV_DOCS):
    return {"severity": severity, "title": title, "detail": detail, "fix": fix,
            "setting": setting, "source": source}


# ---------------------------------------------------------------- reading files

class Deployment:
    def __init__(self):
        self.env = {}      # name -> value; None when the value comes from somewhere this tool can't see
        self.refs = {}     # name -> (variable, default, empty counts as unset) for NAME: ${VARIABLE:-default}
        self.images = []
        self.ports = []    # (host_ip, host_port, container_port) as written; may hold ${...}
        self.sources = []


def _unquote(value):
    value = value.strip()
    if len(value) >= 2 and value[0] == value[-1] and value[0] in "\"'":
        return value[1:-1]
    return value


def _text(raw):
    raw = raw.strip()
    if raw and raw[0] in "\"'":
        end = raw.find(raw[0], 1)
        return raw[1:end] if end > 0 else raw[1:]
    return re.split(r"\s+#", raw, maxsplit=1)[0].strip()


REF = re.compile(r"\$\{([A-Za-z_][A-Za-z0-9_]*)(?:(:?)-([^}]*))?\}")


def _set(dep, name, raw):
    value = _text(raw)
    m = REF.fullmatch(value)
    if m:
        dep.refs[name] = (m.group(1), m.group(3), m.group(2) == ":")
    elif re.match(r"\$[A-Za-z_({]|`", value):
        dep.env[name] = None       # $VAR or $(command): set somewhere else
    else:
        dep.env[name] = value


ENV_ITEM = re.compile(r"^(?:export\s+)?([A-Za-z_][A-Za-z0-9_]*)=(.*)$")
MAP_ITEM = re.compile(r"^\s+([A-Z][A-Z0-9_]*)\s*:\s*(.*)$")
K8S_NAME = re.compile(r"^\s*(?:-\s*)?name:\s*[\"']?([A-Z][A-Z0-9_]*)[\"']?\s*$")
K8S_VALUE = re.compile(r"^\s*value:\s*(.*)$")
K8S_VALUE_FROM = re.compile(r"^\s*valueFrom:")
PORT_ITEM = re.compile(
    r"^\s*-\s*[\"']?(?:(\[[^\]]*\]|\d+\.\d+\.\d+\.\d+|\$\{[^}]*\}):)?(\$\{[^}]*\}|\d+):(\$\{[^}]*\}|\d+)(?:/\w+)?[\"']?\s*$")
IMAGE = re.compile(r"(langgenius/dify-(?:api|web)(?::[A-Za-z0-9_.\-]+)?(?:@sha256:[0-9a-f]{64})?)")


def parse_text(text, name="input"):
    """Reads a .env file, docker-compose.yaml, `docker inspect` JSON or a Kubernetes manifest."""
    dep = Deployment()
    dep.sources.append(name)
    stripped = text.lstrip()
    if stripped[:1] in "[{":
        try:
            _parse_inspect(json.loads(stripped), dep)
            return dep
        except ValueError:
            pass
    pending = None
    for line in text.splitlines():
        if line.lstrip().startswith("#"):
            continue
        item = line.strip()
        if item.startswith("- "):
            item = _unquote(item[2:])
        m = ENV_ITEM.match(item)
        if m:
            _set(dep, m.group(1), m.group(2))
            continue
        m = K8S_NAME.match(line)
        if m:
            pending = m.group(1)
            continue
        if pending:
            m = K8S_VALUE.match(line)
            if m:
                _set(dep, pending, m.group(1))
                pending = None
                continue
            if K8S_VALUE_FROM.match(line):
                dep.env[pending] = None
                pending = None
                continue
        m = MAP_ITEM.match(line)
        if m:
            if m.group(2).strip():
                _set(dep, m.group(1), m.group(2))
            else:
                dep.env[m.group(1)] = None
            continue
        m = PORT_ITEM.match(line)
        if m:
            dep.ports.append((m.group(1) or "", m.group(2), m.group(3)))
    for m in IMAGE.finditer(text):
        if m.group(1) not in dep.images:
            dep.images.append(m.group(1))
    return dep


def _parse_inspect(data, dep):
    for c in data if isinstance(data, list) else [data]:
        if not isinstance(c, dict):
            continue
        config = c.get("Config") or {}
        for item in config.get("Env") or []:
            key, sep, value = item.partition("=")
            if sep:
                dep.env[key] = value
        image = config.get("Image")
        if image and IMAGE.search(image) and image not in dep.images:
            dep.images.append(image)
        bindings = (c.get("HostConfig") or {}).get("PortBindings") or {}
        for container_port, hosts in bindings.items():
            for h in hosts or []:
                dep.ports.append((h.get("HostIp") or "", str(h.get("HostPort") or ""),
                                  container_port.split("/")[0]))


def merge(deps):
    """Files named .env are applied last: Dify's docker/.env wins over docker/envs/*.env."""
    out = Deployment()
    for d in sorted(deps, key=lambda d: d.sources[0] == ".env"):
        out.env.update(d.env)
        out.refs.update(d.refs)
        out.images += [i for i in d.images if i not in out.images]
        out.ports += d.ports
    out.sources = [s for d in deps for s in d.sources]
    return out


def effective_env(dep):
    """The values the containers get: compose references are filled in from the env files."""
    env = dict(dep.env)
    for name, (var, default, colon) in dep.refs.items():
        value = dep.env[var] if var in dep.env else default
        if value == "" and colon:
            value = default
        env[name] = value
    return env


def _resolve(text, env):
    m = REF.fullmatch(text)
    if not m:
        return text
    value = env.get(m.group(1))
    if value is None or (value == "" and m.group(2) == ":"):
        return m.group(3) or ""
    return value


# ---------------------------------------------------------------- checks

def _flag(env, name, default):
    """True/False as Dify reads it, the default when unset or empty, None when the value can't be seen."""
    if name not in env:
        return default
    if env[name] is None:
        return None
    value = env[name].strip().lower()
    if not value:
        return default
    return value in ("1", "true", "yes", "on", "t", "y")


def is_default(name, value):
    """True when the value is a published Dify default or a well-known placeholder."""
    v = (value or "").strip()
    if not v:
        return False
    if "difyai123456" in v.lower():
        return True                # also inside URLs such as CELERY_BROKER_URL
    if not SENSITIVE.search(name):
        return False
    return v.lower() in WEAK or v in PUBLISHED_VALUES or v.startswith(OLD_SECRET_KEY_PREFIX)


def default_credentials(env):
    """(in use, other): names whose values are published defaults or placeholders."""
    store = (env.get("VECTOR_STORE") or "weaviate").strip().lower()
    prefix = VECTOR_PREFIX.get(store, store.upper().replace("-", "_") + "_")
    used, other = [], []
    for name in sorted(env):
        if name == "SECRET_KEY" or not is_default(name, env[name]):
            continue
        (used if name in CORE or name.startswith(prefix) else other).append(name)
    return used, other


def local_sandbox_token(env):
    """True when Dify Agent's local sandbox gets an access token, False when it gets
    none, None when that can't be seen or another sandbox backend is used.
    The compose files pass ${DIFY_AGENT_LOCAL_SANDBOX_AUTH_TOKEN:-${DIFY_AGENT_SHELLCTL_AUTH_TOKEN:-}}
    (the name before 1.17) to the sandbox as SHELLCTL_AUTH_TOKEN."""
    if (env.get("DIFY_AGENT_RUNTIME_BACKEND") or "local").strip().lower() != "local":
        return None
    names = ("DIFY_AGENT_LOCAL_SANDBOX_AUTH_TOKEN", "DIFY_AGENT_SHELLCTL_AUTH_TOKEN", "SHELLCTL_AUTH_TOKEN")
    if any((env.get(n) or "").strip() for n in names):
        return True
    if env.get("SHELLCTL_AUTH_TOKEN") == "":
        return False               # docker inspect of the sandbox container
    if env.get("DIFY_AGENT_LOCAL_SANDBOX_AUTH_TOKEN") != "":
        return None                # not in the files given, or set somewhere else
    if "DIFY_AGENT_SHELLCTL_AUTH_TOKEN" in env and env["DIFY_AGENT_SHELLCTL_AUTH_TOKEN"] is None:
        return None
    return False


def _names(names, limit=12):
    if len(names) <= limit:
        return ", ".join(names)
    return "%s and %d more" % (", ".join(names[:limit]), len(names) - limit)


def check_env(env, version=None):
    """Findings for Dify's environment settings."""
    out = []

    secret = env.get("SECRET_KEY", "")
    if secret is not None:
        secret = secret.strip()
        if secret.startswith(OLD_SECRET_KEY_PREFIX):
            out.append(finding(
                "critical", "SECRET_KEY is the public key from Dify's old example file",
                "Generate a new key with `openssl rand -base64 42`, set SECRET_KEY and restart. Everyone is signed out, signed file links stop working, and plugin OAuth credentials must be set up again.",
                detail="Dify signs sign-in tokens and file links with this key and encrypts OAuth credentials with it, so anyone who knows it can forge a session for any account, including the owner.",
                setting="SECRET_KEY"))
        elif secret.lower() in WEAK:
            out.append(finding(
                "critical", "SECRET_KEY is a well-known placeholder",
                "Generate a new key with `openssl rand -base64 42`, set SECRET_KEY and restart. Anyone who knows the key can forge a session for any account.",
                setting="SECRET_KEY"))
        elif 0 < len(secret) < 32:
            out.append(finding(
                "low", "SECRET_KEY is shorter than Dify suggests (%d characters)" % len(secret),
                "Dify's docs suggest `openssl rand -base64 42`. The key signs every session token and file link.",
                setting="SECRET_KEY"))
        elif not secret and "SECRET_KEY" in env and (version is None or version < (1, 14, 1)):
            out.append(finding(
                "high" if version else "low", "SECRET_KEY is empty",
                "Set it with `openssl rand -base64 42` before the first start. From 1.14.1 on, Dify generates and keeps its own key when SECRET_KEY is empty; before 1.14.1 the compose file fills an empty key with the public example key.",
                setting="SECRET_KEY"))

    used, other = default_credentials(env)
    if used:
        out.append(finding(
            "medium", "%d passwords and keys still have Dify's published default values" % len(used) if len(used) > 1
            else "A password or key still has Dify's published default value",
            "Replace each with a random value (`openssl rand -hex 32`; hex stays valid inside CELERY_BROKER_URL) in docker/.env and restart. Postgres keeps the password it was created with, so for an existing database change it there first (ALTER USER ... WITH PASSWORD) and then in DB_PASSWORD. Change PLUGIN_DAEMON_KEY and the sandbox keys on both sides together. Step by step: %s/blob/main/ROTATE.md" % REPO,
            detail="Settings: %s. Anything that can reach these services inside your network (another container, a plugin, a port published by mistake) can use them; Dify's example file says to replace the agent keys in production." % _names(used),
            setting="credentials", source=ENV_EXAMPLE))
    if other:
        out.append(finding(
            "info", "Placeholder values remain for services you may not use",
            "Only matters if you switch to these services; then give them real credentials.",
            detail="Settings: %s." % _names(other), setting="credentials", source=ENV_EXAMPLE))

    if local_sandbox_token(env) is False:
        out.append(finding(
            "medium", "Dify Agent's local sandbox has no access token (DIFY_AGENT_LOCAL_SANDBOX_AUTH_TOKEN is empty, the default)",
            "Set DIFY_AGENT_LOCAL_SANDBOX_AUTH_TOKEN in docker/.env to a random value (`python3 -c 'import secrets; print(secrets.token_urlsafe(32))'`) and run `docker compose up -d`. The compose file gives the same value to agent_backend and to local_sandbox (as SHELLCTL_AUTH_TOKEN).",
            detail="The sandbox's control API (shellctl) asks for a bearer token only when one is set. Without it, anything that can reach the sandbox, including code running in an agent's shell job, can call that API directly and bypass Dify's per-session tracking of shell jobs (langgenius/dify#38609).",
            setting="DIFY_AGENT_LOCAL_SANDBOX_AUTH_TOKEN", source=SHELLCTL_ISSUE))
    if (env.get("DIFY_AGENT_SHELLCTL_AUTH_TOKEN") or "").strip() and env.get("DIFY_AGENT_LOCAL_SANDBOX_AUTH_TOKEN") == "":
        out.append(finding(
            "info", "DIFY_AGENT_SHELLCTL_AUTH_TOKEN was renamed in Dify 1.17",
            "Move the value to DIFY_AGENT_LOCAL_SANDBOX_AUTH_TOKEN. The compose file still falls back to the old name, but setup scripts and Helm values that only fill the new name leave the sandbox without a token.",
            setting="DIFY_AGENT_SHELLCTL_AUTH_TOKEN", source=ENV_EXAMPLE))

    if env.get("INIT_PASSWORD") == "":
        out.append(finding(
            "low", "No init password (INIT_PASSWORD is empty)",
            "Until setup is finished, anyone who opens /install can create the owner account. Finish setup right after the first start, or set INIT_PASSWORD. Run this check with --url to see whether setup is finished.",
            setting="INIT_PASSWORD"))

    console_cors = env.get("CONSOLE_CORS_ALLOW_ORIGINS", "*")
    if console_cors is not None and console_cors.strip() in ("*", ""):
        out.append(finding(
            "medium", "The console API accepts requests from every origin (CONSOLE_CORS_ALLOW_ORIGINS=*, the default)",
            "Set CONSOLE_CORS_ALLOW_ORIGINS to your console address, e.g. https://dify.example.com (separate several with commas).",
            setting="CONSOLE_CORS_ALLOW_ORIGINS"))
    web_cors = env.get("WEB_API_CORS_ALLOW_ORIGINS", "*")
    if web_cors is not None and web_cors.strip() in ("*", ""):
        out.append(finding(
            "low", "The web app API accepts requests from every origin (WEB_API_CORS_ALLOW_ORIGINS=*, the default)",
            "Fine if you embed Dify apps on other sites. Otherwise set WEB_API_CORS_ALLOW_ORIGINS to the sites that use them.",
            setting="WEB_API_CORS_ALLOW_ORIGINS"))

    urls = [n for n in ("CONSOLE_WEB_URL", "APP_WEB_URL", "CONSOLE_API_URL", "SERVICE_API_URL", "FILES_URL")
            if (env.get(n) or "").strip()]
    plain = [n for n in urls if env[n].strip().startswith("http://")
             and _host_kind(urlsplit(env[n].strip()).hostname or "") != "loopback"]
    if plain:
        out.append(finding(
            "medium", "Dify's addresses use plain HTTP (%s)" % ", ".join(plain),
            "Serve Dify over HTTPS (NGINX_HTTPS_ENABLED=true with a certificate, the bundled Certbot, or a reverse proxy) and change these addresses to https://. Passwords and session tokens otherwise cross the network unencrypted.",
            setting="https"))
    elif not urls and _flag(env, "NGINX_HTTPS_ENABLED", False) is False and "NGINX_HTTPS_ENABLED" in env:
        out.append(finding(
            "low", "Nginx serves plain HTTP (NGINX_HTTPS_ENABLED=false)",
            "Fine behind a reverse proxy that adds HTTPS. Otherwise set NGINX_HTTPS_ENABLED=true with a certificate (Dify's compose file includes Certbot) and set CONSOLE_WEB_URL and APP_WEB_URL to the https:// address.",
            setting="https"))

    if _flag(env, "FORCE_VERIFYING_SIGNATURE", True) is False:
        out.append(finding(
            "high", "Plugins without a valid signature can be installed (FORCE_VERIFYING_SIGNATURE=false)",
            "Set FORCE_VERIFYING_SIGNATURE=true unless you are developing plugins. Plugins run code on your server.",
            setting="FORCE_VERIFYING_SIGNATURE"))

    ssrf = env.get("SSRF_PROXY_HTTP_URL")
    if ssrf is not None and "SSRF_PROXY_HTTP_URL" in env and not ssrf.strip():
        out.append(finding(
            "medium", "Outbound requests skip the SSRF proxy (SSRF_PROXY_HTTP_URL is empty)",
            "Set SSRF_PROXY_HTTP_URL and SSRF_PROXY_HTTPS_URL to http://ssrf_proxy:3128 (the default), so workflow HTTP requests and tools can't reach internal addresses such as cloud metadata.",
            setting="SSRF_PROXY_HTTP_URL"))

    if _flag(env, "ALLOW_UNSAFE_DATA_SCHEME", False):
        out.append(finding(
            "medium", "data: links are allowed in chats (ALLOW_UNSAFE_DATA_SCHEME=true)",
            "Set ALLOW_UNSAFE_DATA_SCHEME=false unless you need it; data: links can carry script or phishing pages.",
            setting="ALLOW_UNSAFE_DATA_SCHEME"))
    if _flag(env, "ALLOW_EMBED", False):
        out.append(finding(
            "low", "Other sites can frame Dify's pages (ALLOW_EMBED=true)",
            "Set ALLOW_EMBED=false unless you embed Dify in an iframe; framing allows clickjacking.",
            setting="ALLOW_EMBED"))

    debug = [n for n in ("DEBUG", "FLASK_DEBUG") if _flag(env, n, False)]
    if debug:
        out.append(finding(
            "low", "Debug mode is on (%s)" % ", ".join(debug),
            "Set %s=false in production: logs get very detailed and errors can show internals." % "=false and ".join(debug),
            setting=debug[0]))
    if (env.get("DEPLOY_ENV") or "").strip().upper() == "DEVELOPMENT":
        out.append(finding(
            "low", "DEPLOY_ENV=DEVELOPMENT", "Use DEPLOY_ENV=PRODUCTION (the default) on a server people use.",
            setting="DEPLOY_ENV"))
    if _flag(env, "ENABLE_REQUEST_LOGGING", False):
        out.append(finding(
            "low", "Request logging is on (ENABLE_REQUEST_LOGGING=true)",
            "Prompts, answers and personal data can end up in the logs. Turn it off when you are done debugging, or protect and rotate the logs.",
            setting="ENABLE_REQUEST_LOGGING"))
    return out


def _tag(image):
    return image.split("@")[0].split("/")[-1].partition(":")[2]


def _everywhere(host_ip):
    return host_ip in ("", "0.0.0.0", "::", "[::]")


def check_deployment(dep, env):
    out = []
    for image in dep.images:
        if "@sha256:" in image:
            continue
        if not parse_version(_tag(image)):
            out.append(finding(
                "low", "The image tag moves (%s)" % image,
                "Pin a release such as %s:%s, as Dify's own compose file does, and update on purpose after reading the release notes." % (image.split(":")[0], LATEST),
                source=ENV_EXAMPLE))
    seen = set()
    for host_ip, host_port, container_port in dep.ports:
        host_ip, host_port, container_port = (_resolve(x, env) for x in (host_ip, host_port, container_port))
        if not (host_port.isdigit() and container_port.isdigit()):
            continue
        if not _everywhere(host_ip) or container_port in WEB_PORTS or (host_port, container_port) in seen:
            continue
        seen.add((host_port, container_port))
        bind = "Remove the port mapping, or publish it as \"127.0.0.1:%s:%s\". Dify's containers reach each other on the Docker network without it. On Linux, ports published by Docker skip ufw and firewalld rules." % (host_port, container_port)
        if container_port == DEBUG_PORT:
            out.append(finding(
                "low", "The plugin remote-debugging port is published on every network interface (host port %s)" % host_port,
                "If you don't develop plugins, remove the mapping or publish it as \"127.0.0.1:%s:%s\". Connecting needs a debugging key from a workspace, but nobody else needs to reach it." % (host_port, container_port),
                setting="ports", source=ENV_EXAMPLE))
            continue
        service, guard, severity = SERVICE_PORTS.get(container_port, ("A service (container port %s)" % container_port, None, "medium"))
        default = guard is not None and is_default(guard, env.get(guard))
        tokenless = container_port == LOCAL_SANDBOX_PORT and local_sandbox_token(env) is False
        if default:
            suffix, detail = (" with a published default credential",
                              "%s is still Dify's published default, so anyone who can reach the port can use it." % guard)
        elif tokenless:
            suffix, detail = (" without an access token",
                              "DIFY_AGENT_LOCAL_SANDBOX_AUTH_TOKEN is empty, so anyone who can reach the port can use the sandbox's shell control API.")
        else:
            suffix, detail = "", ""
        out.append(finding(
            "critical" if default or tokenless else severity,
            "%s is published on every network interface (host port %s)%s" % (service, host_port, suffix),
            bind, detail=detail, setting="ports", source=SHELLCTL_ISSUE if tokenless else ENV_EXAMPLE))
    return out


def image_version(dep):
    for image in dep.images:
        tag = _tag(image)
        v = parse_version(tag)
        if v:
            return v, tag
    return None, None


def check_version(version, label=""):
    if version is None:
        return [finding(
            "info", "Dify version unknown",
            "Include docker-compose.yaml (it pins langgenius/dify-api), or look at the version in the console's About dialog and compare it with %s." % ADVISORY_PAGE,
            source=ADVISORY_PAGE)]
    hits = []
    for first, fixed, ids, summary, source in ADVISORIES:
        if (first is None or version >= parse_version(first)) and version < parse_version(fixed):
            hits.append("%s (fixed in %s): %s %s" % (ids, fixed, summary, source))
    if not hits:
        return []
    return [finding(
        "high", "Dify %s has %d known advisor%s" % (label or ".".join(map(str, version)), len(hits), "y" if len(hits) == 1 else "ies"),
        "Update to %s or newer (the latest is %s at the time of this data); 1.16.0 also closed a SQL injection and an SSRF bypass. Back up the database and volumes first and follow the upgrade notes." % (SAFE_VERSION, LATEST),
        detail="\n".join(hits), source=ADVISORY_PAGE)]


# ---------------------------------------------------------------- live check of your own server

def _fetch(url, headers=None, timeout=10):
    h = {"User-Agent": "dify-hardening-check/" + __version__}
    h.update(headers or {})
    req = urllib.request.Request(url, headers=h)
    try:
        with urllib.request.urlopen(req, timeout=timeout) as r:
            return r.status, {k.lower(): v for k, v in r.headers.items()}, r.read(1000000)
    except urllib.error.HTTPError as e:
        return e.code, {k.lower(): v for k, v in e.headers.items()}, e.read(1000000)


def _json(body):
    try:
        return json.loads(body.decode("utf-8", "replace"))
    except ValueError:
        return None


def _host_kind(host):
    if host in ("localhost", "localhost.localdomain"):
        return "loopback"
    try:
        ip = ipaddress.ip_address(host.strip("[]"))
    except ValueError:
        return "name"
    if ip.is_loopback:
        return "loopback"
    return "private" if ip.is_private else "public"


def check_url(url, fetch=_fetch):
    """Reads what any visitor's browser can see before signing in: the console's
    setup status, its CORS answer and the start page's response headers."""
    base = url.rstrip("/")
    parts = urlsplit(base)
    if parts.scheme not in ("http", "https") or not parts.hostname:
        raise ValueError("--url needs to start with http:// or https://")
    try:
        status, headers, body = fetch(base + "/console/api/setup", {"Origin": PROBE_ORIGIN})
    except (urllib.error.URLError, OSError) as e:
        return [finding("info", "Couldn't reach %s" % base, "Check the address, or run the check from a machine that can reach it.",
                        detail=str(getattr(e, "reason", e)), source=REPO)]
    setup = _json(body) if status == 200 else None
    if not isinstance(setup, dict) or setup.get("step") not in ("not_started", "finished"):
        return [finding("info", "%s/console/api/setup didn't answer like Dify (HTTP %s)" % (base, status),
                        "Give the address you open Dify's console at in your browser.", source=REPO)]
    out = []
    if setup["step"] == "not_started":
        try:
            _, _, init_body = fetch(base + "/console/api/init", None)
            init = _json(init_body)
        except (urllib.error.URLError, OSError):
            init = None
        if isinstance(init, dict) and init.get("status") == "not_started":
            out.append(finding(
                "medium", "Setup isn't finished; an init password guards it",
                "Open %s/install now and create the owner account. Until then, anyone who learns INIT_PASSWORD can create it." % base,
                setting="INIT_PASSWORD"))
        else:
            out.append(finding(
                "critical", "Setup isn't finished: the next visitor to /install creates the owner account",
                "Open %s/install now and create the owner account, or take the server off the network until you do. Next time, set INIT_PASSWORD before the first start." % base,
                setting="setup"))
    acao = headers.get("access-control-allow-origin", "")
    if acao in ("*", PROBE_ORIGIN):
        out.append(finding(
            "medium", "The console API accepts cross-origin requests from any website",
            "Set CONSOLE_CORS_ALLOW_ORIGINS to your console address, e.g. %s://%s, and restart." % (parts.scheme, parts.netloc),
            detail="A request with Origin: %s was answered with Access-Control-Allow-Origin: %s." % (PROBE_ORIGIN, acao),
            setting="CONSOLE_CORS_ALLOW_ORIGINS"))

    kind = _host_kind(parts.hostname)
    if parts.scheme == "http" and kind != "loopback":
        out.append(finding(
            {"private": "low", "name": "medium", "public": "high"}[kind],
            "Passwords and session tokens cross the network unencrypted (http://)",
            "Serve Dify over HTTPS (NGINX_HTTPS_ENABLED=true with a certificate, the bundled Certbot, or a reverse proxy) and stop publishing the plain HTTP port.",
            setting="https"))
    try:
        _, page_headers, _ = fetch(base + "/", None)
    except (urllib.error.URLError, OSError):
        page_headers = {}
    missing = []
    if parts.scheme == "https" and "strict-transport-security" not in page_headers:
        missing.append("Strict-Transport-Security")
    csp = page_headers.get("content-security-policy", "")
    if "x-frame-options" not in page_headers and "frame-ancestors" not in csp:
        missing.append("X-Frame-Options")
    if "x-content-type-options" not in page_headers:
        missing.append("X-Content-Type-Options")
    if page_headers and missing:
        out.append(finding(
            "low", "Security headers missing: %s" % ", ".join(missing),
            "Add them at your reverse proxy or in Dify's nginx template (docker/nginx/conf.d/default.conf.template), e.g. `add_header X-Frame-Options SAMEORIGIN;` and `add_header X-Content-Type-Options nosniff;`. Without X-Frame-Options other sites can frame the console (clickjacking, GHSA-jhgq-cx3f-vj5p).",
            setting="headers", source=ADVISORY_PAGE + "/GHSA-jhgq-cx3f-vj5p"))
    return out


# ---------------------------------------------------------------- output

def counts(findings):
    c = {s: 0 for s in SEVERITIES}
    for f in findings:
        c[f["severity"]] += 1
    return c


def _sorted(findings):
    return sorted(findings, key=lambda f: RANK[f["severity"]])


FOOTER = ("Checks follow Dify's environment documentation (%s), its example env files and advisories checked on %s. "
          "General technical information, not a security certification. "
          "Made with AI agents for MV2 of Munim, Inc.: %s" % (ENV_DOCS, DATA_DATE, REPO))
REVIEW = "Want a written review of a shared Dify server? See %s#written-review" % REPO


def render_text(findings, sources, version_label):
    lines = ["Dify hardening check %s" % __version__,
             "Checked: %s" % ", ".join(sources),
             "Dify version: %s" % (version_label or "unknown"), ""]
    if not findings:
        lines.append("No findings.")
    for f in _sorted(findings):
        lines.append("%-8s  %s" % (f["severity"].upper(), f["title"]))
        for part in [f["detail"], "Fix: " + f["fix"]]:
            for para in (part.split("\n") if part else []):
                lines += textwrap.wrap(para, 96, initial_indent=" " * 10, subsequent_indent=" " * 10)
        lines.append("")
    c = counts(findings)
    lines.append("Summary: " + ", ".join("%d %s" % (c[s], s) for s in SEVERITIES))
    lines += [""] + textwrap.wrap(FOOTER, 100) + [REVIEW]
    return "\n".join(lines)


def render_markdown(findings, sources, version_label):
    c = counts(findings)
    lines = ["## Dify hardening check",
             "Version: **%s** | Checked: %s | %s" % (
                 version_label or "unknown", ", ".join(sources),
                 ", ".join("%d %s" % (c[s], s) for s in SEVERITIES if c[s]) or "no findings"), ""]
    current = None
    for f in _sorted(findings):
        if f["severity"] != current:
            current = f["severity"]
            lines += ["### " + current.capitalize(), ""]
        text = "- **%s**" % f["title"]
        if f["detail"]:
            text += " " + f["detail"].replace("\n", "; ")
        text += " *Fix:* %s ([source](%s))" % (f["fix"], f["source"])
        lines.append(text)
    lines += ["", "_%s_" % FOOTER, "", REVIEW]
    return "\n".join(lines)


def _read(path):
    with open(path, encoding="utf-8", errors="replace") as f:
        return f.read()


def run(files=(), url=None, read=_read, fetch=_fetch):
    """Returns (findings, sources, version label)."""
    findings, sources = [], []
    version, tag, label = None, None, None
    if url:
        findings += check_url(url, fetch)
        sources.append(url)
    if files:
        dep = merge([parse_text(read(p), os.path.basename(p)) for p in files])
        env = effective_env(dep)
        sources += dep.sources
        version, tag = image_version(dep)
        if version:
            label = "%s (from the image tag)" % tag
        findings += check_env(env, version) + check_deployment(dep, env)
    findings += check_version(version, tag or "")
    return findings, sources, label


def main(argv=None):
    p = argparse.ArgumentParser(
        prog="dify_hardening_check.py",
        description="Check a self-hosted Dify deployment for published default credentials, risky settings, "
                    "open ports and known advisories. Read-only; secret values are never printed.")
    p.add_argument("files", nargs="*", help="docker/.env, docker/docker-compose.yaml, docker/envs/*.env, "
                                            "`docker inspect` JSON or a Kubernetes manifest")
    p.add_argument("--url", help="the address of a Dify server you run, e.g. https://dify.example.com")
    p.add_argument("--json", action="store_true", help="print JSON")
    p.add_argument("--markdown", action="store_true", help="print Markdown")
    p.add_argument("--fail-on", choices=SEVERITIES[:4] + ["never"], default="high",
                   help="exit with 1 when a finding is this severe or worse (default: high)")
    p.add_argument("--version", action="version", version=__version__)
    args = p.parse_args(argv)
    if not args.files and not args.url:
        p.error("give at least one file or --url")
    try:
        findings, sources, label = run(args.files, args.url)
    except (OSError, ValueError) as e:
        print("error: %s" % e, file=sys.stderr)
        return 2
    if args.json:
        print(json.dumps({"tool": "dify-hardening-check", "version": __version__, "data_date": DATA_DATE,
                          "checked": sources, "dify_version": label, "counts": counts(findings),
                          "findings": _sorted(findings)}, indent=2))
    elif args.markdown:
        print(render_markdown(findings, sources, label))
    else:
        print(render_text(findings, sources, label))
    if args.fail_on != "never" and any(RANK[f["severity"]] <= RANK[args.fail_on] for f in findings):
        return 1
    return 0


if __name__ == "__main__":
    sys.exit(main())
