import contextlib
import io
import json
import os
import sys
import tempfile
import unittest
import urllib.error

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))

import dify_hardening_check as dhc  # noqa: E402


def titles(findings):
    return [f["title"] for f in findings]


def by_severity(findings, severity):
    return [f for f in findings if f["severity"] == severity]


def settings(findings):
    return {f["setting"] for f in findings}


# Shortened from Dify's docker/.env.example (main, October 2026).
ENV = """# ------------------------------
SECRET_KEY=
INIT_PASSWORD=
CONSOLE_WEB_URL=
APP_WEB_URL=
DB_USERNAME=postgres
DB_PASSWORD=difyai123456
DB_DATABASE=dify
REDIS_PASSWORD=difyai123456
CELERY_BROKER_URL=redis://:difyai123456@redis:6379/1
VECTOR_STORE=weaviate
WEAVIATE_API_KEY=%(weaviate)s
WEAVIATE_AUTHENTICATION_APIKEY_USERS=hello@dify.ai
CODE_EXECUTION_API_KEY=dify-sandbox
SANDBOX_API_KEY=dify-sandbox
PLUGIN_DAEMON_KEY=%(daemon)s
DIFY_AGENT_API_TOKEN=%(agent)s
WEB_API_CORS_ALLOW_ORIGINS=*
CONSOLE_CORS_ALLOW_ORIGINS=*
NGINX_HTTPS_ENABLED=false
EXPOSE_PLUGIN_DEBUGGING_PORT=5003
OPENSEARCH_PASSWORD=admin
TIDB_PUBLIC_KEY=dify
SSRF_PROXY_HTTP_URL=http://ssrf_proxy:3128
""" % {"weaviate": dhc.PUBLISHED_KEYS["WEAVIATE_API_KEY"], "daemon": dhc.PUBLISHED_KEYS["PLUGIN_DAEMON_KEY"],
       "agent": dhc.PUBLISHED_KEYS["DIFY_AGENT_API_TOKEN"]}

# Shortened from Dify's docker/docker-compose.yaml.
COMPOSE = """services:
  api:
    image: langgenius/dify-api:1.14.2
    environment:
      MODE: api
  redis:
    image: redis:6-alpine
    environment:
      REDISCLI_AUTH: ${REDIS_PASSWORD:-difyai123456}
  plugin_daemon:
    image: langgenius/dify-plugin-daemon:0.6.10-local
    environment:
      SERVER_KEY: ${PLUGIN_DAEMON_KEY:-lYkiYYT6owG}
    ports:
      - "${EXPOSE_PLUGIN_DEBUGGING_PORT:-5003}:${PLUGIN_DEBUGGING_PORT:-5003}"
  nginx:
    image: nginx:latest
    ports:
      - "${EXPOSE_NGINX_PORT:-80}:${NGINX_PORT:-80}"
      - "${EXPOSE_NGINX_SSL_PORT:-443}:${NGINX_SSL_PORT:-443}"
"""

# Shortened from Dify's docker/docker-compose.middleware.yaml (source deployments).
MIDDLEWARE = """services:
  db_postgres:
    image: postgres:15-alpine
    environment:
      POSTGRES_PASSWORD: ${DB_PASSWORD:-difyai123456}
    ports:
      - "${EXPOSE_POSTGRES_PORT:-5432}:5432"
  redis:
    image: redis:6-alpine
    ports:
      - "127.0.0.1:${EXPOSE_REDIS_PORT:-6379}:6379"
  ssrf_proxy:
    image: ubuntu/squid:latest
    ports:
      - "${EXPOSE_SANDBOX_PORT:-8194}:${SSRF_SANDBOX_PROXY_PORT:-8194}"
  weaviate:
    image: cr.weaviate.io/semitechnologies/weaviate:1.39.2
    ports:
      - 8080:8080
"""

K8S = """        env:
          - name: SECRET_KEY
            valueFrom:
              secretKeyRef:
                name: dify
                key: secret
          - name: CONSOLE_CORS_ALLOW_ORIGINS
            value: "https://dify.example.com"
          - name: DB_PASSWORD
            value: difyai123456
"""


class ParseTests(unittest.TestCase):
    def test_env_file(self):
        text = ("# comment\nexport DEBUG=\"true\"\nAPP_WEB_URL=https://dify.example.com  # public\n"
                "INIT_PASSWORD='s3cret'\nDB_HOST=${DB_HOST_FROM_SHELL}\nSECRET_KEY=$(openssl rand -base64 42)\n")
        dep = dhc.parse_text(text, ".env")
        self.assertEqual(dep.env["DEBUG"], "true")
        self.assertEqual(dep.env["APP_WEB_URL"], "https://dify.example.com")
        self.assertEqual(dep.env["INIT_PASSWORD"], "s3cret")
        self.assertEqual(dep.refs["DB_HOST"], ("DB_HOST_FROM_SHELL", None, False))
        self.assertIsNone(dep.env["SECRET_KEY"])

    def test_compose_references_are_filled_from_env(self):
        dep = dhc.merge([dhc.parse_text(COMPOSE, "docker-compose.yaml"), dhc.parse_text(ENV, ".env")])
        env = dhc.effective_env(dep)
        self.assertEqual(env["REDISCLI_AUTH"], "difyai123456")
        self.assertEqual(env["SERVER_KEY"], dhc.PUBLISHED_KEYS["PLUGIN_DAEMON_KEY"])
        self.assertEqual(env["MODE"], "api")
        self.assertEqual(dep.images, ["langgenius/dify-api:1.14.2"])
        self.assertEqual(dhc.image_version(dep), ((1, 14, 2), "1.14.2"))
        self.assertEqual(len(dep.ports), 3)
        self.assertEqual(dep.sources, ["docker-compose.yaml", ".env"])

    def test_dot_env_wins_over_envs_folder(self):
        dep = dhc.merge([dhc.parse_text("DB_PASSWORD=from-dotenv\n", ".env"),
                         dhc.parse_text("DB_PASSWORD=difyai123456\n", "security.env")])
        self.assertEqual(dhc.effective_env(dep)["DB_PASSWORD"], "from-dotenv")

    def test_empty_value_falls_back_to_compose_default(self):
        # Before 1.14.1 the compose file had SECRET_KEY: ${SECRET_KEY:-<example key>}.
        compose = "    environment:\n      SECRET_KEY: ${SECRET_KEY:-%sXYZ}\n" % dhc.OLD_SECRET_KEY_PREFIX
        dep = dhc.merge([dhc.parse_text(compose, "docker-compose.yaml"), dhc.parse_text("SECRET_KEY=\n", ".env")])
        env = dhc.effective_env(dep)
        self.assertTrue(env["SECRET_KEY"].startswith(dhc.OLD_SECRET_KEY_PREFIX))
        self.assertEqual(by_severity(dhc.check_env(env), "critical")[0]["setting"], "SECRET_KEY")

    def test_docker_inspect(self):
        data = [{"Config": {"Env": ["DB_PASSWORD=difyai123456", "PATH=/usr/bin"], "Image": "langgenius/dify-api:1.17.1"},
                 "HostConfig": {}},
                {"Config": {"Env": [], "Image": "postgres:15-alpine"},
                 "HostConfig": {"PortBindings": {"5432/tcp": [{"HostIp": "0.0.0.0", "HostPort": "5432"}]}}}]
        dep = dhc.parse_text(json.dumps(data), "inspect.json")
        self.assertEqual(dep.images, ["langgenius/dify-api:1.17.1"])
        self.assertEqual(dep.ports, [("0.0.0.0", "5432", "5432")])
        found = dhc.check_deployment(dep, dhc.effective_env(dep))
        self.assertEqual(len(by_severity(found, "critical")), 1)

    def test_kubernetes(self):
        env = dhc.effective_env(dhc.parse_text(K8S, "deployment.yaml"))
        self.assertIsNone(env["SECRET_KEY"])
        self.assertEqual(env["CONSOLE_CORS_ALLOW_ORIGINS"], "https://dify.example.com")
        found = dhc.check_env(env)
        self.assertNotIn("SECRET_KEY", settings(found))
        self.assertNotIn("CONSOLE_CORS_ALLOW_ORIGINS", settings(found))
        self.assertIn("credentials", settings(found))


class EnvCheckTests(unittest.TestCase):
    def test_stock_example_env(self):
        env = dhc.effective_env(dhc.parse_text(ENV, ".env"))
        found = dhc.check_env(env)
        self.assertEqual(by_severity(found, "critical") + by_severity(found, "high"), [])
        creds = [f for f in found if f["setting"] == "credentials"]
        self.assertEqual([f["severity"] for f in creds], ["medium", "info"])
        self.assertEqual(creds[0]["title"], "8 passwords and keys still have Dify's published default values")
        for name in ("DB_PASSWORD", "CELERY_BROKER_URL", "WEAVIATE_API_KEY", "DIFY_AGENT_API_TOKEN"):
            self.assertIn(name, creds[0]["detail"])
        self.assertNotIn("WEAVIATE_AUTHENTICATION_APIKEY_USERS", creds[0]["detail"])
        self.assertIn("OPENSEARCH_PASSWORD", creds[1]["detail"])
        self.assertIn("TIDB_PUBLIC_KEY", creds[1]["detail"])
        self.assertEqual({f["setting"] for f in by_severity(found, "medium")}, {"credentials", "CONSOLE_CORS_ALLOW_ORIGINS"})
        self.assertEqual({f["setting"] for f in by_severity(found, "low")},
                         {"SECRET_KEY", "INIT_PASSWORD", "WEB_API_CORS_ALLOW_ORIGINS", "https"})

    def test_secret_key(self):
        old = dhc.OLD_SECRET_KEY_PREFIX + "abcdefghijklmnopqrstuvwxyz0123456789"
        self.assertEqual(by_severity(dhc.check_env({"SECRET_KEY": old}), "critical")[0]["setting"], "SECRET_KEY")
        self.assertEqual(by_severity(dhc.check_env({"SECRET_KEY": "changeme"}), "critical")[0]["setting"], "SECRET_KEY")
        self.assertIn("12 characters", titles(dhc.check_env({"SECRET_KEY": "abcdefghijkl"}))[0])
        empty_old = [f for f in dhc.check_env({"SECRET_KEY": ""}, (1, 13, 0)) if f["setting"] == "SECRET_KEY"]
        self.assertEqual(empty_old[0]["severity"], "high")
        self.assertEqual([f for f in dhc.check_env({"SECRET_KEY": ""}, (1, 17, 1)) if f["setting"] == "SECRET_KEY"], [])
        self.assertEqual([f for f in dhc.check_env({"SECRET_KEY": "x" * 56}) if f["setting"] == "SECRET_KEY"], [])

    def test_secrets_never_printed(self):
        env = dhc.effective_env(dhc.parse_text(ENV + "SECRET_KEY=abcdefgh\n", ".env"))
        text = json.dumps(dhc.check_env(env))
        for value in ["difyai123456", "dify-sandbox", "abcdefgh"] + list(dhc.PUBLISHED_VALUES):
            self.assertNotIn(value, text)

    def test_changed_credentials_and_hardened_settings(self):
        env = {"DB_PASSWORD": "q8Vh2mZ0rT4w", "REDIS_PASSWORD": "Lk3pX9sQ1n", "SECRET_KEY": "k" * 56,
               "INIT_PASSWORD": "set", "CONSOLE_CORS_ALLOW_ORIGINS": "https://dify.example.com",
               "WEB_API_CORS_ALLOW_ORIGINS": "https://www.example.com",
               "CONSOLE_WEB_URL": "https://dify.example.com", "APP_WEB_URL": "https://dify.example.com"}
        self.assertEqual(dhc.check_env(env), [])

    def test_vector_store_selects_credentials(self):
        env = {"VECTOR_STORE": "qdrant", "QDRANT_API_KEY": "difyai123456",
               "WEAVIATE_API_KEY": dhc.PUBLISHED_KEYS["WEAVIATE_API_KEY"]}
        self.assertEqual(dhc.default_credentials(env), (["QDRANT_API_KEY"], ["WEAVIATE_API_KEY"]))
        self.assertEqual(dhc.default_credentials({"DB_PASSWORD": "difyai123456"}), (["DB_PASSWORD"], []))
        found = dhc.check_env({"DB_PASSWORD": "difyai123456"})
        self.assertIn("A password or key still has", [f for f in found if f["setting"] == "credentials"][0]["title"])

    def test_risky_switches(self):
        env = {"FORCE_VERIFYING_SIGNATURE": "false", "SSRF_PROXY_HTTP_URL": "", "ALLOW_UNSAFE_DATA_SCHEME": "true",
               "ALLOW_EMBED": "true", "DEBUG": "true", "FLASK_DEBUG": "1", "DEPLOY_ENV": "DEVELOPMENT",
               "ENABLE_REQUEST_LOGGING": "True", "CONSOLE_WEB_URL": "http://dify.example.com",
               "APP_WEB_URL": "http://localhost"}
        found = dhc.check_env(env)
        self.assertEqual(settings(by_severity(found, "high")), {"FORCE_VERIFYING_SIGNATURE"})
        self.assertTrue({"SSRF_PROXY_HTTP_URL", "ALLOW_UNSAFE_DATA_SCHEME", "https"} <= settings(by_severity(found, "medium")))
        self.assertIn("(CONSOLE_WEB_URL)", [f for f in found if f["setting"] == "https"][0]["title"])
        self.assertTrue({"ALLOW_EMBED", "DEBUG", "DEPLOY_ENV", "ENABLE_REQUEST_LOGGING"} <= settings(by_severity(found, "low")))
        self.assertIn("Set DEBUG=false and FLASK_DEBUG=false", [f for f in found if f["setting"] == "DEBUG"][0]["fix"])


class DeploymentTests(unittest.TestCase):
    def test_stock_compose_only_flags_debug_port(self):
        dep = dhc.merge([dhc.parse_text(COMPOSE, "docker-compose.yaml"), dhc.parse_text(ENV, ".env")])
        found = dhc.check_deployment(dep, dhc.effective_env(dep))
        self.assertEqual(len(found), 1)
        self.assertEqual(found[0]["severity"], "low")
        self.assertIn("remote-debugging port", found[0]["title"])

    def test_middleware_ports(self):
        dep = dhc.merge([dhc.parse_text(MIDDLEWARE, "docker-compose.middleware.yaml"), dhc.parse_text(ENV, ".env")])
        found = dhc.check_deployment(dep, dhc.effective_env(dep))
        crit = titles(by_severity(found, "critical"))
        self.assertEqual(len(crit), 3)           # Postgres, the sandbox and Weaviate, all with published defaults
        self.assertTrue(any(t.startswith("PostgreSQL") for t in crit))
        self.assertFalse(any("Redis" in t for t in titles(found)))    # bound to 127.0.0.1
        self.assertIn("127.0.0.1:5432:5432", by_severity(found, "critical")[0]["fix"])

    def test_changed_password_lowers_severity_and_overrides_port(self):
        env_text = "DB_PASSWORD=q8Vh2mZ0rT4w\nEXPOSE_POSTGRES_PORT=15432\n"
        dep = dhc.merge([dhc.parse_text(MIDDLEWARE, "m.yaml"), dhc.parse_text(env_text, ".env")])
        found = [f for f in dhc.check_deployment(dep, dhc.effective_env(dep)) if f["title"].startswith("PostgreSQL")]
        self.assertEqual(found[0]["severity"], "high")
        self.assertIn("host port 15432", found[0]["title"])

    def test_moving_tag(self):
        dep = dhc.parse_text("    image: langgenius/dify-web:latest\n", "c.yaml")
        self.assertIn("tag moves", titles(dhc.check_deployment(dep, {}))[0])


class VersionTests(unittest.TestCase):
    def test_versions(self):
        self.assertEqual(dhc.check_version((1, 14, 2), "1.14.2")[0]["title"], "Dify 1.14.2 has 1 known advisory")
        self.assertEqual(dhc.check_version((1, 13, 0))[0]["title"], "Dify 1.13.0 has 3 known advisories")
        found = dhc.check_version((1, 10, 1), "1.10.1-fix.1")
        self.assertEqual(found[0]["title"], "Dify 1.10.1-fix.1 has 7 known advisories")
        self.assertIn("CVE-2026-21866", found[0]["detail"])
        self.assertNotIn("GHSA-fw4f-cghv-2v33", found[0]["detail"])
        self.assertEqual(dhc.check_version((1, 16, 0)), [])
        self.assertEqual(dhc.check_version((1, 17, 1)), [])
        self.assertEqual(dhc.check_version(None)[0]["severity"], "info")
        self.assertEqual(dhc.parse_version("1.10.1-fix.1"), (1, 10, 1))
        self.assertIsNone(dhc.parse_version("latest"))


def fake_fetch(setup, init=None, headers=None, page_headers=None, status=200):
    def fetch(url, h):
        if url.endswith("/console/api/setup"):
            body = setup if isinstance(setup, bytes) else json.dumps(setup).encode()
            return status, headers or {}, body
        if url.endswith("/console/api/init"):
            return 200, {}, json.dumps(init or {}).encode()
        return 200, page_headers or {}, b"<html></html>"
    return fetch


class UrlTests(unittest.TestCase):
    def test_unfinished_setup_without_init_password(self):
        found = dhc.check_url("http://8.8.8.8", fake_fetch(
            {"step": "not_started"}, {"status": "finished"}, {"access-control-allow-origin": "https://cors-check.invalid"},
            {"content-type": "text/html"}))
        self.assertEqual(settings(by_severity(found, "critical")), {"setup"})
        self.assertEqual(settings(by_severity(found, "high")), {"https"})
        self.assertEqual(settings(by_severity(found, "medium")), {"CONSOLE_CORS_ALLOW_ORIGINS"})
        self.assertEqual(settings(by_severity(found, "low")), {"headers"})

    def test_unfinished_setup_with_init_password(self):
        found = dhc.check_url("http://192.168.1.20", fake_fetch({"step": "not_started"}, {"status": "not_started"}))
        self.assertEqual(by_severity(found, "critical"), [])
        self.assertEqual(settings(by_severity(found, "medium")), {"INIT_PASSWORD"})
        self.assertEqual([f for f in found if f["setting"] == "https"][0]["severity"], "low")

    def test_hardened_server(self):
        page = {"strict-transport-security": "max-age=31536000", "x-frame-options": "SAMEORIGIN",
                "x-content-type-options": "nosniff"}
        found = dhc.check_url("https://dify.example.com/", fake_fetch(
            {"step": "finished", "setup_at": "2026-10-01T00:00:00"}, None,
            {"access-control-allow-origin": "https://dify.example.com"}, page))
        self.assertEqual(found, [])

    def test_unreachable_and_not_dify(self):
        def down(url, h):
            raise urllib.error.URLError("refused")
        self.assertEqual(dhc.check_url("http://localhost", down)[0]["severity"], "info")
        found = dhc.check_url("http://localhost", fake_fetch(b"<html>", status=404))
        self.assertIn("didn't answer like Dify", found[0]["title"])
        with self.assertRaises(ValueError):
            dhc.check_url("ftp://example.com")


class CliTests(unittest.TestCase):
    def run_main(self, argv):
        out = io.StringIO()
        with contextlib.redirect_stdout(out):
            rc = dhc.main(argv)
        return rc, out.getvalue()

    def test_json_and_exit_codes(self):
        with tempfile.TemporaryDirectory() as d:
            env_path = os.path.join(d, ".env")
            compose_path = os.path.join(d, "docker-compose.middleware.yaml")
            with open(env_path, "w", encoding="utf-8") as f:
                f.write(ENV)
            with open(compose_path, "w", encoding="utf-8") as f:
                f.write(MIDDLEWARE)
            rc, out = self.run_main(["--json", compose_path, env_path])
            self.assertEqual(rc, 1)
            self.assertNotIn("difyai123456", out)
            data = json.loads(out)
            self.assertEqual(data["counts"]["critical"], 3)
            self.assertEqual(data["checked"], ["docker-compose.middleware.yaml", ".env"])
            self.assertIsNone(data["dify_version"])
            rc, out = self.run_main([env_path, "--fail-on", "never"])
            self.assertEqual(rc, 0)
            self.assertIn("MEDIUM", out)
            self.assertIn("written-review", out)
            rc, out = self.run_main(["--markdown", "--fail-on", "never", env_path])
            self.assertIn("### Medium", out)
        with self.assertRaises(SystemExit):
            with contextlib.redirect_stderr(io.StringIO()):
                dhc.main([])

    def test_run_with_injected_reader(self):
        findings, sources, label = dhc.run(["docker-compose.yaml"], read=lambda p: COMPOSE)
        self.assertEqual(sources, ["docker-compose.yaml"])
        self.assertEqual(label, "1.14.2 (from the image tag)")
        self.assertEqual(titles(by_severity(findings, "high")), ["Dify 1.14.2 has 1 known advisory"])


if __name__ == "__main__":
    unittest.main()
