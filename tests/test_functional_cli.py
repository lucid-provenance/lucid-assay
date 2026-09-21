"""Tests for cli/functional.py -- the standalone `functional-adequacy` subcommand."""
import contextlib
import io
import json
import os
import sys
import tempfile
import unittest
from pathlib import Path

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from cli.functional import main, parse_args

_CONTRACT = {
    "framework": "pytest",
    "journeys": [{"id": "ci-one", "tier": "ci"}, {"id": "cd-one", "tier": "cd"}],
}


def _junit(*tags):
    props = "".join(f'<property name="cuj" value="@cuj:{t}"/>' for t in tags)
    return f'<testsuites><testsuite><testcase classname="t" name="n"><properties>{props}</properties></testcase></testsuite></testsuites>'


class ParseArgsTests(unittest.TestCase):
    def test_functional_tier_is_required(self):
        with contextlib.redirect_stderr(io.StringIO()), self.assertRaises(SystemExit) as ctx:
            parse_args([])
        self.assertEqual(ctx.exception.code, 2)

    def test_functional_tier_only_accepts_ci_or_cd(self):
        for bad in ("both", "staging", ""):
            with self.subTest(bad=bad), contextlib.redirect_stderr(io.StringIO()), self.assertRaises(SystemExit):
                parse_args(["--functional-tier", bad])

    def test_defaults(self):
        args = parse_args(["--functional-tier", "cd"])
        self.assertEqual(args.functional_tier, "cd")
        self.assertEqual(args.repo_dir, ".")
        self.assertIsNone(args.functional_report)
        self.assertIsNone(args.functional_env)
        self.assertIsNone(args.functional_report_uri)
        self.assertIsNone(args.out)

    def test_report_is_repeatable_and_ordered(self):
        args = parse_args(["--functional-tier", "cd", "--functional-report", "a", "--functional-report", "b"])
        self.assertEqual(args.functional_report, ["a", "b"])

    def test_every_flag_is_parsed(self):
        args = parse_args(["--functional-tier", "ci", "--repo-dir", "/r", "--functional-env", "staging",
                           "--functional-report-uri", "https://x", "--out", "o.json"])
        self.assertEqual((args.repo_dir, args.functional_env, args.functional_report_uri, args.out),
                         ("/r", "staging", "https://x", "o.json"))


class MainTests(unittest.TestCase):
    def setUp(self):
        self._tmp = tempfile.TemporaryDirectory()
        self.dir = Path(self._tmp.name)
        (self.dir / ".lucid").mkdir()
        (self.dir / ".lucid" / "functional-verification.json").write_text(json.dumps(_CONTRACT), encoding="utf-8")

    def tearDown(self):
        self._tmp.cleanup()

    def _run(self, *argv):
        out, err = io.StringIO(), io.StringIO()
        with contextlib.redirect_stdout(out), contextlib.redirect_stderr(err):
            code = main(list(argv))
        return code, out.getvalue(), err.getvalue()

    def test_prints_the_predicate_json_to_stdout_and_exits_zero_on_a_met_result(self):
        report = self.dir / "r.xml"
        report.write_text(_junit("cd-one"), encoding="utf-8")
        code, out, err = self._run("--repo-dir", str(self.dir), "--functional-tier", "cd",
                                   "--functional-report", str(report), "--functional-env", "staging")
        self.assertEqual((code, err), (0, ""))
        self.assertTrue(out.endswith("\n"))
        doc = json.loads(out)
        self.assertTrue(doc["met"])
        self.assertEqual(doc["target_env"], "staging")
        self.assertEqual(doc["adequacy"]["tier"], "cd")
        self.assertEqual(doc["adequacy"]["declared"], ["cd-one"])
        self.assertEqual(doc["adequacy"]["deferred"], ["ci-one"])

    def test_exits_zero_even_when_unmet_so_the_caller_can_record_it(self):
        code, out, _ = self._run("--repo-dir", str(self.dir), "--functional-tier", "cd",
                                 "--functional-report", str(self.dir / "wrote-nothing.xml"))
        self.assertEqual(code, 0)
        doc = json.loads(out)
        self.assertFalse(doc["met"])
        self.assertEqual(doc["reason_code"], "execution_aborted")

    def test_output_is_two_space_indented_sorted_json_with_a_trailing_newline(self):
        _, out, _ = self._run("--repo-dir", str(self.dir), "--functional-tier", "ci")
        self.assertEqual(out, json.dumps(json.loads(out), indent=2, sort_keys=True) + "\n")
        self.assertIn('\n  "adequacy": {', out)

    def test_out_file_has_the_same_exact_serialization_as_stdout(self):
        target = self.dir / "result.json"
        self._run("--repo-dir", str(self.dir), "--functional-tier", "ci", "--out", str(target))
        _, out, _ = self._run("--repo-dir", str(self.dir), "--functional-tier", "ci")
        self.assertEqual(target.read_text(encoding="utf-8"), out)

    def test_output_is_deterministic_sorted_json(self):
        args = ("--repo-dir", str(self.dir), "--functional-tier", "ci")
        first_run = self._run(*args)[1]
        second_run = self._run(*args)[1]
        self.assertEqual(first_run, second_run)
        keys = list(json.loads(first_run).keys())
        self.assertEqual(keys, sorted(keys))

    def test_repeatable_reports_are_aggregated(self):
        (self.dir / "a.xml").write_text(_junit("cd-one"), encoding="utf-8")
        (self.dir / "b.xml").write_text(_junit(), encoding="utf-8")
        _, out, _ = self._run("--repo-dir", str(self.dir), "--functional-tier", "cd",
                              "--functional-report", str(self.dir / "a.xml"), "--functional-report", str(self.dir / "b.xml"))
        self.assertEqual(json.loads(out)["metrics"]["total"], 2)

    def test_out_writes_the_file_prints_nothing_and_exits_zero(self):
        target = self.dir / "result.json"
        code, out, err = self._run("--repo-dir", str(self.dir), "--functional-tier", "ci", "--out", str(target))
        self.assertEqual((code, out, err), (0, "", ""))
        self.assertEqual(json.loads(target.read_text(encoding="utf-8"))["adequacy"]["tier"], "ci")

    def test_an_unsafe_out_path_exits_one_with_a_message_and_writes_nothing(self):
        code, out, err = self._run("--repo-dir", str(self.dir), "--functional-tier", "ci", "--out", "bad\x00path")
        self.assertEqual(code, 1)
        self.assertEqual(out, "")
        self.assertTrue(err.startswith("ERROR: "))

    def test_report_uri_is_embedded_verbatim(self):
        _, out, _ = self._run("--repo-dir", str(self.dir), "--functional-tier", "ci", "--functional-report-uri", "https://ci/artifact/1")
        self.assertEqual(json.loads(out)["report_uri"], "https://ci/artifact/1")

    def test_an_invalid_contract_is_a_result_not_a_crash(self):
        (self.dir / ".lucid" / "functional-verification.json").write_text(
            json.dumps({"framework": "pytest", "journeys": [{"id": "a", "tier": "nope"}]}), encoding="utf-8")
        code, out, _ = self._run("--repo-dir", str(self.dir), "--functional-tier", "cd")
        self.assertEqual(code, 0)
        self.assertEqual(json.loads(out)["reason_code"], "config_invalid")


if __name__ == "__main__":
    unittest.main()
