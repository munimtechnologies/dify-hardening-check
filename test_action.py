import io
import json
import os
import sys
import tempfile
import unittest

HERE = os.path.dirname(os.path.abspath(__file__))
sys.path.insert(0, HERE)

import dify_hardening_check as dhc  # noqa: E402
import github_action  # noqa: E402

ENV = "SECRET_KEY=\nDB_PASSWORD=difyai123456\nREDIS_PASSWORD=difyai123456\n"

# Shortened from Dify's docker/docker-compose.middleware.yaml.
MIDDLEWARE = """services:
  db_postgres:
    image: postgres:15-alpine
    environment:
      POSTGRES_PASSWORD: ${DB_PASSWORD:-difyai123456}
    ports:
      - "${EXPOSE_POSTGRES_PORT:-5432}:5432"
"""


def postgres(env_text):
    dep = dhc.merge([dhc.parse_text(MIDDLEWARE, "docker-compose.middleware.yaml"), dhc.parse_text(env_text, ".env")])
    return [f for f in dhc.check_deployment(dep, dhc.effective_env(dep)) if f["title"].startswith("PostgreSQL")]


class CveTests(unittest.TestCase):
    def test_default_database_password_names_the_cve(self):
        creds = [f for f in dhc.check_env({"DB_PASSWORD": "difyai123456"}) if f["setting"] == "credentials"]
        self.assertIn(dhc.DEFAULT_DB_CVE, creds[0]["detail"])
        self.assertIn("DB_PASSWORD holds", creds[0]["detail"])
        creds = [f for f in dhc.check_env({"REDIS_PASSWORD": "difyai123456"}) if f["setting"] == "credentials"]
        self.assertNotIn(dhc.DEFAULT_DB_CVE, creds[0]["detail"])

    def test_published_postgres_port(self):
        found = postgres(ENV)
        self.assertEqual(found[0]["severity"], "critical")
        self.assertIn(dhc.DEFAULT_DB_CVE, found[0]["detail"])
        self.assertEqual(found[0]["source"], dhc.DEFAULT_DB_CVE_URL)
        found = postgres("DB_PASSWORD=q8Vh2mZ0rT4w\n")
        self.assertEqual(found[0]["severity"], "high")
        self.assertNotIn(dhc.DEFAULT_DB_CVE, found[0]["detail"])
        self.assertEqual(found[0]["source"], dhc.ENV_EXAMPLE)

    def test_value_never_printed(self):
        dep = dhc.merge([dhc.parse_text(MIDDLEWARE, "m.yaml"), dhc.parse_text(ENV, ".env")])
        env = dhc.effective_env(dep)
        self.assertNotIn("difyai123456", json.dumps(dhc.check_env(env) + dhc.check_deployment(dep, env)))


class ExpandTests(unittest.TestCase):
    def test_paths_and_wildcards(self):
        with tempfile.TemporaryDirectory() as d:
            os.makedirs(os.path.join(d, "docker", "envs"))
            for name in (os.path.join("docker", ".env"), os.path.join("docker", "docker-compose.yaml"),
                         os.path.join("docker", "envs", "web.env"), os.path.join("docker", "envs", "api.env")):
                with open(os.path.join(d, name), "w", encoding="utf-8") as f:
                    f.write("DEBUG=false\n")
            files, missing = github_action.expand(
                "docker/.env docker/docker-compose.yaml\ndocker/envs/*.env docker/missing.env nope/*.env docker", root=d)
            expected = [os.path.join(d, "docker", ".env"), os.path.join(d, "docker", "docker-compose.yaml"),
                        os.path.join(d, "docker", "envs", "api.env"), os.path.join(d, "docker", "envs", "web.env")]
            self.assertEqual([os.path.normpath(p) for p in files], [os.path.normpath(p) for p in expected])
            self.assertEqual(missing, ["docker/missing.env", "nope/*.env", "docker"])
        self.assertEqual(github_action.expand(""), ([], []))

    def test_escape(self):
        self.assertEqual(github_action._escape("50% done\r\nnext"), "50%25 done%0D%0Anext")


class MainTests(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.d = self.tmp.name
        self.env_path = os.path.join(self.d, ".env")
        self.compose_path = os.path.join(self.d, "docker-compose.middleware.yaml")
        for path, text in ((self.env_path, ENV), (self.compose_path, MIDDLEWARE)):
            with open(path, "w", encoding="utf-8") as f:
                f.write(text)
        self.summary = os.path.join(self.d, "summary.md")
        self.output = os.path.join(self.d, "output.txt")

    def tearDown(self):
        self.tmp.cleanup()

    def main(self, **extra):
        environ = {"CHECK_FILES": "%s\n%s %s" % (self.compose_path, self.env_path, os.path.join(self.d, "missing.env")),
                   "CHECK_URL": "", "GITHUB_STEP_SUMMARY": self.summary, "GITHUB_OUTPUT": self.output,
                   "RUNNER_TEMP": self.d}
        environ.update(extra)
        out = io.StringIO()
        rc = github_action.main(environ, out)
        return rc, out.getvalue()

    def read(self, path):
        with open(path, encoding="utf-8") as f:
            return f.read()

    def test_report_annotations_and_outputs(self):
        rc, out = self.main(CHECK_FAIL_ON="high")
        self.assertEqual(rc, 1)
        self.assertIn("::warning::%s not found, skipped" % os.path.join(self.d, "missing.env"), out)
        self.assertIn("::error::CRITICAL: PostgreSQL is published on every network interface (host port 5432) "
                      "with a published default credential", out)
        self.assertIn("::warning::MEDIUM: The console API accepts requests from every origin", out)
        self.assertIn("Dify hardening check %s" % dhc.__version__, out)
        summary = self.read(self.summary)
        self.assertIn("## Dify hardening check", summary)
        self.assertIn(dhc.DEFAULT_DB_CVE, summary)
        outputs = self.read(self.output).splitlines()
        self.assertIn("critical=1", outputs)
        self.assertIn("high=0", outputs)
        report = os.path.join(self.d, github_action.REPORT_NAME)
        self.assertIn("report=%s" % report, outputs)
        data = json.loads(self.read(report))
        self.assertEqual(data["counts"]["critical"], 1)
        self.assertEqual(data["checked"], ["docker-compose.middleware.yaml", ".env"])
        for text in (out, summary, self.read(report)):
            self.assertNotIn("difyai123456", text)

    def test_fail_on(self):
        self.assertEqual(self.main(CHECK_FAIL_ON="never")[0], 0)
        self.assertEqual(self.main(CHECK_FAIL_ON="critical")[0], 1)
        self.assertEqual(self.main(CHECK_FAIL_ON="")[0], 1)          # default: high
        rc, out = self.main(CHECK_FAIL_ON="severe")
        self.assertEqual(rc, 2)
        self.assertIn("::error::fail-on must be", out)

    def test_nothing_to_check(self):
        rc, out = self.main(CHECK_FILES=os.path.join(self.d, "nope.env"))
        self.assertEqual(rc, 2)
        self.assertIn("::error::No files to check", out)


@unittest.skipUnless(os.path.exists(os.path.join(HERE, "action.yml")), "action.yml not next to the tests")
class ActionFileTests(unittest.TestCase):
    def test_action_yml(self):
        with open(os.path.join(HERE, "action.yml"), encoding="utf-8") as f:
            text = f.read()
        self.assertIn("using: composite", text)
        self.assertIn("$GITHUB_ACTION_PATH/github_action.py", text)
        for name in ("files", "url", "fail-on"):
            self.assertIn("\n  %s:\n" % name, text)
            self.assertIn("${{ inputs.%s }}" % name, text)
        for name in ("CHECK_FILES", "CHECK_URL", "CHECK_FAIL_ON"):
            self.assertIn(name + ":", text)
        description = [line for line in text.splitlines() if line.startswith("description:")][0]
        self.assertLess(len(description.split(":", 1)[1].strip()), 125)    # GitHub Marketplace limit


if __name__ == "__main__":
    unittest.main()
