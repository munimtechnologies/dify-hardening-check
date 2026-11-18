"""Dify 1.20.0 (18 November 2026) stopped loading docker/envs/core-services/shared.env
and turned OPENAPI_ENABLED on by default. Apache-2.0."""

import json
import os
import sys
import tempfile
import unittest

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))

import dify_hardening_check as dhc  # noqa: E402

# Shortened from Dify 1.20.0's docker/ folder: a minimal .env and tracked defaults.
LAYOUT = {
    ".env": "COMPOSE_PROFILES=weaviate,postgresql\nDIFY_AGENT_LOCAL_SANDBOX_AUTH_TOKEN=f0e1d2c3b4a5\n",
    os.path.join("envs", "databases", "db-postgres.defaults"):
        "DB_PASSWORD=${DB_PASSWORD:-q8Vh2mZ0rT4w}\nPOSTGRES_PASSWORD=${DB_PASSWORD:-q8Vh2mZ0rT4w}\n",
    os.path.join("envs", "core-services", "plugin-daemon.defaults"):
        "SERVER_KEY=${PLUGIN_DAEMON_KEY:-%s}\n" % dhc.PUBLISHED_KEYS["PLUGIN_DAEMON_KEY"],
    os.path.join("envs", "core-services", "api-worker.defaults"):
        "CONSOLE_CORS_ALLOW_ORIGINS=${CONSOLE_CORS_ALLOW_ORIGINS-*}\n",
}
SHARED = os.path.join("envs", "core-services", "shared.env")
SHARED_TEXT = "CONSOLE_CORS_ALLOW_ORIGINS=https://dify.example.com\nPLUGIN_DAEMON_KEY=Zx81kQ0pLm77\n"


def compose(version):
    return "services:\n  api:\n    image: langgenius/dify-api:%s\n" % version


class SharedEnvTests(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.d = self.tmp.name
        for name, text in LAYOUT.items():
            self.write(name, text)
        self.write(SHARED, SHARED_TEXT)

    def tearDown(self):
        self.tmp.cleanup()

    def write(self, name, text):
        path = os.path.join(self.d, name)
        os.makedirs(os.path.dirname(path), exist_ok=True)
        with open(path, "w", encoding="utf-8") as f:
            f.write(text)

    def by_setting(self, findings, setting):
        return [f for f in findings if f["setting"] == setting]

    def test_folder_includes_shared_env(self):
        names = [os.path.relpath(p, self.d) for p in dhc.expand_paths([self.d])]
        self.assertIn(SHARED, names)

    def test_120_ignores_shared_env(self):
        self.write("docker-compose.yaml", compose("1.20.0"))
        findings, sources, label = dhc.run([self.d])
        self.assertEqual(label, "1.20.0 (from the image tag)")
        self.assertNotIn("shared.env", sources)
        self.assertIn("shared.env (not loaded by Dify 1.20.0)", sources)
        retired = self.by_setting(findings, "shared.env")
        self.assertEqual([f["severity"] for f in retired], ["medium"])
        self.assertIn("2 settings in it no longer apply", retired[0]["title"])
        self.assertIn("CONSOLE_CORS_ALLOW_ORIGINS", retired[0]["detail"])
        self.assertIn("PLUGIN_DAEMON_KEY", retired[0]["detail"])
        self.assertIn("api-worker.env", retired[0]["fix"])
        # The values Dify really gets now: CORS falls back to *, the daemon key to the published one.
        self.assertEqual(len(self.by_setting(findings, "CONSOLE_CORS_ALLOW_ORIGINS")), 1)
        creds = self.by_setting(findings, "credentials")
        self.assertIn("SERVER_KEY", creds[0]["detail"])
        self.assertEqual(len(self.by_setting(findings, "OPENAPI_ENABLED")), 1)
        text = json.dumps(findings) + json.dumps(sources)
        for value in ["Zx81kQ0pLm77", "q8Vh2mZ0rT4w", "f0e1d2c3b4a5"] + list(dhc.PUBLISHED_VALUES):
            self.assertNotIn(value, text)

    def test_119_still_reads_shared_env(self):
        self.write("docker-compose.yaml", compose("1.19.0"))
        findings, sources, _ = dhc.run([self.d])
        self.assertIn("shared.env", sources)
        retired = self.by_setting(findings, "shared.env")
        self.assertEqual([f["severity"] for f in retired], ["info"])
        self.assertIn("stops working in Dify 1.20", retired[0]["title"])
        self.assertEqual(self.by_setting(findings, "CONSOLE_CORS_ALLOW_ORIGINS"), [])
        self.assertEqual(self.by_setting(findings, "credentials"), [])
        self.assertEqual(self.by_setting(findings, "OPENAPI_ENABLED"), [])
        self.assertNotIn("Zx81kQ0pLm77", json.dumps(findings))

    def test_unknown_version_reads_shared_env_and_says_so(self):
        findings, _, label = dhc.run([self.d])
        self.assertIsNone(label)
        retired = self.by_setting(findings, "shared.env")
        self.assertEqual([f["severity"] for f in retired], ["info"])
        self.assertIn("docker-compose.yaml", retired[0]["fix"])
        self.assertEqual(self.by_setting(findings, "CONSOLE_CORS_ALLOW_ORIGINS"), [])

    def test_120_with_settings_moved_to_api_worker_env(self):
        self.write("docker-compose.yaml", compose("1.20.0"))
        self.write(os.path.join("envs", "core-services", "api-worker.env"),
                   "CONSOLE_CORS_ALLOW_ORIGINS=https://dify.example.com\n")
        self.write(".env", LAYOUT[".env"] + "PLUGIN_DAEMON_KEY=Zx81kQ0pLm77\n")
        findings, _, _ = dhc.run([self.d])
        retired = self.by_setting(findings, "shared.env")
        self.assertEqual([f["severity"] for f in retired], ["info"])
        self.assertIn("also set in another file", retired[0]["title"])
        self.assertEqual(self.by_setting(findings, "CONSOLE_CORS_ALLOW_ORIGINS"), [])
        self.assertEqual(self.by_setting(findings, "credentials"), [])

    def test_harmless_setting_only_is_low(self):
        self.write("docker-compose.yaml", compose("1.20.0"))
        self.write(SHARED, "LOG_LEVEL=INFO\n")
        findings, _, _ = dhc.run([self.d])
        retired = self.by_setting(findings, "shared.env")
        self.assertEqual([f["severity"] for f in retired], ["low"])
        self.assertIn("1 setting in it no longer applies", retired[0]["title"])


class PrecedenceTests(unittest.TestCase):
    def test_api_worker_env_wins_over_shared_env_in_119(self):
        dep = dhc.merge([dhc.parse_text("X_SETTING=b\n", "api-worker.env"),
                         dhc.parse_text("X_SETTING=a\n", "shared.env"),
                         dhc.parse_text("X_SETTING=c\n", "api-worker.defaults")])
        self.assertEqual(dhc.effective_env(dep)["X_SETTING"], "b")
        dep = dhc.merge([dhc.parse_text("X_SETTING=d\n", ".env"),
                         dhc.parse_text("X_SETTING=b\n", "api-worker.env")])
        self.assertEqual(dhc.effective_env(dep)["X_SETTING"], "d")


class OpenApiAndVersionTests(unittest.TestCase):
    def test_openapi_default_on_from_120(self):
        self.assertEqual([f["severity"] for f in dhc.check_env({}, (1, 20, 0)) if f["setting"] == "OPENAPI_ENABLED"],
                         ["info"])
        self.assertEqual([f for f in dhc.check_env({"OPENAPI_ENABLED": "false"}, (1, 20, 0))
                          if f["setting"] == "OPENAPI_ENABLED"], [])
        self.assertEqual([f for f in dhc.check_env({}, (1, 19, 0)) if f["setting"] == "OPENAPI_ENABLED"], [])
        self.assertEqual([f for f in dhc.check_env({}) if f["setting"] == "OPENAPI_ENABLED"], [])

    def test_120_has_no_known_advisories(self):
        self.assertEqual(dhc.check_version((1, 20, 0)), [])
        self.assertEqual(dhc.LATEST, "1.20.0")
        self.assertIn("shared.env", dhc.check_version((1, 17, 1))[0]["fix"])


if __name__ == "__main__":
    unittest.main()
