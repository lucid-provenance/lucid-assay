"""Direct unit tests for cli/main.py's own parse_args()/main()/
_dispatch_standalone_subcommand() -- previously exercised only indirectly
(via subprocess-based end-to-end tests elsewhere in this suite), which
left parse_args()'s ~900-line argument table and main()'s own dispatch/
gate logic with zero direct mutation-testing pressure. Help text wording
itself is deliberately not asserted here -- mutating a help string's
case/wording is not a real test-quality gap the way a wrong default,
dest, type, or required flag is; nobody diffs --help output character-by-
character in practice, so this file focuses on parse_args' actual
behavioral surface instead."""
import argparse
import json
import os
import sys
import tempfile
import types
import unittest
from pathlib import Path
from unittest.mock import ANY, MagicMock, patch

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from cli.main import _dispatch_standalone_subcommand, main, parse_args


def _min_argv(**overrides):
    """The minimal argv that satisfies every `required=True` flag plus
    the custom image-ref/image-digest-or-subject-name/subject-digest
    validation parse_args() enforces by hand after p.parse_args()."""
    base = {
        "--junit-xml": "junit.xml",
        "--coverage-report": "coverage.xml",
        "--head-sha": "a" * 40,
        "--repository": "org/repo",
        "--branch": "main",
        "--image-ref": "ghcr.io/org/repo",
        "--image-digest": "sha256:" + "b" * 64,
    }
    base.update(overrides)
    argv: list = []
    for flag, value in base.items():
        if value is None:
            continue
        argv += [flag, value]
    return argv


class ParseArgsRequiredFlagsTests(unittest.TestCase):
    """Each required=True flag: dropping it must exit(2); pins both the
    `required=True` value itself and that argparse's own required-arg
    enforcement wasn't quietly disabled."""

    def _missing(self, flag):
        argv = _min_argv()
        # Remove exactly one `--flag value` pair.
        idx = argv.index(flag)
        del argv[idx : idx + 2]
        return argv

    def test_missing_junit_xml_exits_2(self):
        with self.assertRaises(SystemExit) as ctx:
            parse_args(self._missing("--junit-xml"))
        self.assertEqual(ctx.exception.code, 2)

    def test_missing_coverage_report_exits_2(self):
        with self.assertRaises(SystemExit) as ctx:
            parse_args(self._missing("--coverage-report"))
        self.assertEqual(ctx.exception.code, 2)

    def test_missing_head_sha_exits_2(self):
        with self.assertRaises(SystemExit) as ctx:
            parse_args(self._missing("--head-sha"))
        self.assertEqual(ctx.exception.code, 2)

    def test_missing_repository_exits_2(self):
        with self.assertRaises(SystemExit) as ctx:
            parse_args(self._missing("--repository"))
        self.assertEqual(ctx.exception.code, 2)

    def test_missing_branch_exits_2(self):
        with self.assertRaises(SystemExit) as ctx:
            parse_args(self._missing("--branch"))
        self.assertEqual(ctx.exception.code, 2)


class ParseArgsSubjectResolutionTests(unittest.TestCase):
    """The hand-rolled --image-ref/--image-digest vs --subject-name/
    --subject-digest validation at the bottom of parse_args() -- argparse
    itself can't express "one of these two pairs is required", so this is
    real, non-argparse-generated logic worth pinning directly."""

    def test_neither_pair_given_errors(self):
        with self.assertRaises(SystemExit) as ctx:
            parse_args(_min_argv(**{"--image-ref": None, "--image-digest": None}))
        self.assertEqual(ctx.exception.code, 2)

    def test_image_ref_without_digest_errors(self):
        with self.assertRaises(SystemExit) as ctx:
            parse_args(_min_argv(**{"--image-digest": None}))
        self.assertEqual(ctx.exception.code, 2)

    def test_image_digest_without_ref_errors(self):
        with self.assertRaises(SystemExit) as ctx:
            parse_args(_min_argv(**{"--image-ref": None}))
        self.assertEqual(ctx.exception.code, 2)

    def test_subject_name_and_digest_alone_satisfy_the_requirement(self):
        args = parse_args(
            _min_argv(**{"--image-ref": None, "--image-digest": None})
            + ["--subject-name", "my-lambda-fn", "--subject-digest", "sha256:" + "c" * 64]
        )
        # Both resolve onto the same image_ref/image_digest attributes.
        self.assertEqual(args.image_ref, "my-lambda-fn")
        self.assertEqual(args.image_digest, "sha256:" + "c" * 64)

    def test_subject_name_without_subject_digest_errors(self):
        with self.assertRaises(SystemExit) as ctx:
            parse_args(
                _min_argv(**{"--image-ref": None, "--image-digest": None}) + ["--subject-name", "my-lambda-fn"]
            )
        self.assertEqual(ctx.exception.code, 2)

    def test_subject_name_takes_precedence_over_image_ref_when_both_given(self):
        # `args.subject_name or args.image_ref` -- subject_name wins.
        args = parse_args(_min_argv() + ["--subject-name", "my-lambda-fn"])
        self.assertEqual(args.image_ref, "my-lambda-fn")

    def test_subject_digest_takes_precedence_over_image_digest_when_both_given(self):
        args = parse_args(_min_argv() + ["--subject-digest", "sha256:" + "d" * 64])
        self.assertEqual(args.image_digest, "sha256:" + "d" * 64)

    def test_image_ref_alone_is_used_when_no_subject_name_given(self):
        args = parse_args(_min_argv())
        self.assertEqual(args.image_ref, "ghcr.io/org/repo")
        self.assertEqual(args.image_digest, "sha256:" + "b" * 64)


class ParseArgsDefaultsTests(unittest.TestCase):
    """Every flag's real default value, in one place -- a mutant that
    changes any single default (e.g. 90 -> 91, 0.80 -> 1.8, False -> True)
    fails exactly one of these assertions."""

    def test_all_defaults(self):
        args = parse_args(_min_argv())
        self.assertEqual(args.coverage_format, "cobertura")
        self.assertIsNone(args.base_sha)
        self.assertEqual(args.repo_dir, ".")
        self.assertIsNone(args.pr_number)
        self.assertEqual(args.pr_approvers, "")
        self.assertEqual(args.pr_required_approvals, 0)
        self.assertEqual(args.pr_review_state, "not_applicable")
        self.assertIsNone(args.github_token)
        self.assertIsNone(args.sarif)
        self.assertIsNone(args.sbom)
        self.assertIsNone(args.license_curations)
        self.assertIsNone(args.sonar_metrics)
        self.assertIsNone(args.coverage_contexts)
        self.assertEqual(args.patch_coverage_min, 0.80)
        self.assertEqual(args.overall_coverage_min, 0.60)
        self.assertEqual(args.min_rcs, 0)
        self.assertEqual(args.out, "attestation.unsigned.json")
        self.assertFalse(args.sign)
        self.assertFalse(args.dry_run_sign)
        self.assertFalse(args.emit_slsa_provenance)
        self.assertIsNone(args.slsa_provenance_out)
        self.assertIsNone(args.sbom_statement_out)
        self.assertIsNone(args.sarif_reports_statement_out)
        self.assertFalse(args.skip_perf_budget_check)
        self.assertFalse(args.skip_mutation_testing)
        self.assertEqual(args.mutation_testing_timeout, 90)
        self.assertEqual(args.mutation_testing_min_sample, 3)
        self.assertIsNone(args.mutation_report_out)
        self.assertFalse(args.debug)

    def test_dest_names_on_the_namespace(self):
        # Pins every explicit dest=... against a mutant that renames or
        # nulls it -- accessed by attribute, so a wrong dest would raise
        # AttributeError here instead of just silently reading a default.
        args = parse_args(_min_argv())
        for dest in (
            "coverage_report", "license_curations", "sonar_metrics", "coverage_contexts",
            "emit_slsa_provenance", "slsa_provenance_out", "sbom_statement_out",
            "sarif_reports_statement_out", "mutation_testing_timeout", "mutation_testing_min_sample",
            "mutation_report_out",
        ):
            self.assertTrue(hasattr(args, dest), f"missing expected dest: {dest}")


class ParseArgsChoicesAndTypesTests(unittest.TestCase):
    def test_coverage_format_accepts_each_real_choice(self):
        for value in ("cobertura", "lcov", "jacoco"):
            args = parse_args(_min_argv(**{"--coverage-format": value}))
            self.assertEqual(args.coverage_format, value)

    def test_coverage_format_rejects_an_invalid_choice(self):
        with self.assertRaises(SystemExit) as ctx:
            parse_args(_min_argv(**{"--coverage-format": "not-a-real-format"}))
        self.assertEqual(ctx.exception.code, 2)

    def test_pr_number_parses_as_int(self):
        args = parse_args(_min_argv() + ["--pr-number", "42"])
        self.assertEqual(args.pr_number, 42)
        self.assertIsInstance(args.pr_number, int)

    def test_pr_number_rejects_non_integer(self):
        with self.assertRaises(SystemExit) as ctx:
            parse_args(_min_argv() + ["--pr-number", "not-an-int"])
        self.assertEqual(ctx.exception.code, 2)

    def test_pr_required_approvals_parses_as_int_with_real_default(self):
        args = parse_args(_min_argv() + ["--pr-required-approvals", "2"])
        self.assertEqual(args.pr_required_approvals, 2)

    def test_patch_coverage_min_parses_as_float(self):
        args = parse_args(_min_argv() + ["--patch-coverage-min", "0.95"])
        self.assertEqual(args.patch_coverage_min, 0.95)

    def test_overall_coverage_min_parses_as_float(self):
        args = parse_args(_min_argv() + ["--overall-coverage-min", "0.5"])
        self.assertEqual(args.overall_coverage_min, 0.5)

    def test_min_rcs_parses_as_int(self):
        args = parse_args(_min_argv() + ["--min-rcs", "65"])
        self.assertEqual(args.min_rcs, 65)

    def test_mutation_testing_timeout_parses_as_int_overriding_the_default(self):
        args = parse_args(_min_argv() + ["--mutation-testing-timeout", "600"])
        self.assertEqual(args.mutation_testing_timeout, 600)

    def test_mutation_testing_min_sample_parses_as_int_overriding_the_default(self):
        args = parse_args(_min_argv() + ["--mutation-testing-min-sample", "5"])
        self.assertEqual(args.mutation_testing_min_sample, 5)

    def test_sarif_is_appendable_and_none_when_absent(self):
        self.assertIsNone(parse_args(_min_argv()).sarif)
        args = parse_args(_min_argv() + ["--sarif", "a.sarif", "--sarif", "b.sarif"])
        self.assertEqual(args.sarif, ["a.sarif", "b.sarif"])


class ParseArgsBooleanFlagsTests(unittest.TestCase):
    """Every store_true flag: false by default, true only when the exact
    real flag string is passed -- kills default=False->True flips and
    dest renames uniformly."""

    def test_each_boolean_flag_flips_only_when_passed(self):
        flag_to_dest = {
            "--sign": "sign",
            "--dry-run-sign": "dry_run_sign",
            "--emit-slsa-provenance": "emit_slsa_provenance",
            "--skip-perf-budget-check": "skip_perf_budget_check",
            "--skip-mutation-testing": "skip_mutation_testing",
            "--debug": "debug",
        }
        for flag, dest in flag_to_dest.items():
            with self.subTest(flag=flag):
                self.assertFalse(getattr(parse_args(_min_argv()), dest))
                self.assertTrue(getattr(parse_args(_min_argv() + [flag]), dest))


class DispatchStandaloneSubcommandTests(unittest.TestCase):
    """`lucid-assay {verify,sign,provenance} ...` dispatch -- each branch's
    exact raw_argv[0] string comparison and argv-slice-passed-through."""

    def test_empty_argv_dispatches_to_nothing(self):
        self.assertIsNone(_dispatch_standalone_subcommand([]))

    def test_unrecognized_first_token_dispatches_to_nothing(self):
        self.assertIsNone(_dispatch_standalone_subcommand(["--junit-xml", "x.xml"]))

    def test_verify_dispatches_with_the_remaining_argv_and_returns_its_exit_code(self):
        fake_verify_main = MagicMock(return_value=7)
        with patch.dict(sys.modules, {"cli.verify": types.SimpleNamespace(main=fake_verify_main)}):
            result = _dispatch_standalone_subcommand(["verify", "envelope.json", "--dry-run"])
        fake_verify_main.assert_called_once_with(["envelope.json", "--dry-run"])
        self.assertEqual(result, 7)

    def test_sign_dispatches_with_the_remaining_argv_and_returns_its_exit_code(self):
        fake_sign_main = MagicMock(return_value=3)
        with patch.dict(sys.modules, {"cli.sign": types.SimpleNamespace(main=fake_sign_main)}):
            result = _dispatch_standalone_subcommand(["sign", "statement.json"])
        fake_sign_main.assert_called_once_with(["statement.json"])
        self.assertEqual(result, 3)

    def test_provenance_dispatches_with_the_remaining_argv_and_returns_its_exit_code(self):
        fake_provenance_main = MagicMock(return_value=9)
        with patch.dict(sys.modules, {"cli.provenance": types.SimpleNamespace(main=fake_provenance_main)}):
            result = _dispatch_standalone_subcommand(["provenance", "--repo-dir", "."])
        fake_provenance_main.assert_called_once_with(["--repo-dir", "."])
        self.assertEqual(result, 9)


def _fake_ast_metrics():
    return types.SimpleNamespace(
        total_assertions=10, total_test_functions=5, empty_test_bodies=0,
        tautological_assertions=0, skipped_test_functions=0, valid_test_functions=5,
        languages={},
    )


class MainPipelineTests(unittest.TestCase):
    """main()'s own dispatch/gate logic -- every external pipeline call is
    mocked so this exercises only main()'s real control flow (the "run"
    alias strip, --skip-mutation-testing short-circuiting the mutmut call,
    the min-rcs gate, and the --debug branch), not any of those modules'
    own behavior (each already has its own dedicated test file)."""

    def setUp(self):
        self._tmp = tempfile.TemporaryDirectory()
        self.addCleanup(self._tmp.cleanup)
        self.out_path = str(Path(self._tmp.name) / "attestation.unsigned.json")

    def _patches(self, rcs_value=90):
        """Returns (context_manager, mocks_dict) -- patch.multiple's own
        __enter__ return value only includes DEFAULT-sentinel entries, not
        explicit Mock instances passed in directly, so the dict of mocks
        actually used is built and returned separately here instead."""
        rcs = types.SimpleNamespace(value=rcs_value)
        coverage = types.SimpleNamespace(overall_line_rate=0.9)
        mocks = dict(
            parse_junit_xml=MagicMock(return_value=types.SimpleNamespace()),
            parse_cobertura=MagicMock(return_value=coverage),
            parse_jacoco=MagicMock(return_value=coverage),
            parse_lcov=MagicMock(return_value=coverage),
            compute_patch_coverage=MagicMock(return_value=MagicMock()),
            inspect_branch_governance=MagicMock(return_value=MagicMock()),
            inspect_commit_author=MagicMock(return_value=MagicMock()),
            _ingest_sarif=MagicMock(return_value=None),
            _ingest_sbom=MagicMock(return_value=None),
            sha256_file=MagicMock(return_value="deadbeef"),
            _load_license_curations=MagicMock(return_value={}),
            _merge_sbom_into_sarif=MagicMock(return_value=None),
            inspect_test_suite=MagicMock(return_value=_fake_ast_metrics()),
            run_mutation_testing=MagicMock(return_value=MagicMock()),
            compute_patch_modified_lines=MagicMock(return_value={}),
            score_pipeline=MagicMock(return_value=rcs),
            _detect_lockfile_dependencies=MagicMock(return_value=[]),
            _compute_real_coverage_analysis=MagicMock(return_value=None),
            _evaluate_s2c2f_controls=MagicMock(return_value=None),
            build_statement=MagicMock(return_value={"mock": "statement"}),
            _build_sbom_artifact_block=MagicMock(return_value=None),
            _maybe_emit_slsa_provenance=MagicMock(return_value=None),
            _maybe_emit_sbom_statement=MagicMock(return_value=None),
            _maybe_emit_sarif_reports_statement=MagicMock(return_value=None),
            upload_to_worm_async=MagicMock(return_value=None),
            _maybe_sign=MagicMock(return_value=(0, 0, None)),
            _maybe_annotate_verdict=MagicMock(return_value=None),
            _emit_stage_profile=MagicMock(return_value=None),
            _emit_run_warnings=MagicMock(return_value=None),
        )
        return patch.multiple("cli.main", **mocks), mocks

    def _argv(self, min_rcs="80", extra_flags=(), **overrides):
        return _min_argv(**{"--out": self.out_path, "--min-rcs": min_rcs, **overrides}) + [
            "--skip-mutation-testing",
            *extra_flags,
        ]

    def test_happy_path_returns_0_and_writes_the_statement(self):
        cm, _ = self._patches(rcs_value=90)
        with cm:
            rc = main(self._argv())
        self.assertEqual(rc, 0)
        with open(self.out_path, encoding="utf-8") as f:
            self.assertEqual(json.load(f), {"mock": "statement"})

    def test_rcs_below_min_rcs_returns_exactly_1(self):
        cm, _ = self._patches(rcs_value=50)
        with cm:
            rc = main(self._argv())
        self.assertEqual(rc, 1)

    def test_rcs_exactly_at_min_rcs_still_passes(self):
        # Pins the `<` (not `<=`) in `if rcs.value < args.min_rcs`.
        cm, _ = self._patches(rcs_value=80)
        with cm:
            rc = main(self._argv())
        self.assertEqual(rc, 0)

    def test_debug_flag_triggers_stage_profile_emission(self):
        cm, mocks = self._patches(rcs_value=90)
        with cm:
            main(self._argv(extra_flags=["--debug"]))
        mocks["_emit_stage_profile"].assert_called_once()

    def test_no_debug_flag_never_emits_stage_profile(self):
        cm, mocks = self._patches(rcs_value=90)
        with cm:
            main(self._argv())
        mocks["_emit_stage_profile"].assert_not_called()

    def test_run_alias_is_stripped_and_behaves_identically(self):
        cm, _ = self._patches(rcs_value=90)
        with cm:
            rc = main(["run"] + self._argv())
        self.assertEqual(rc, 0)

    def test_skip_mutation_testing_short_circuits_the_real_mutmut_call(self):
        cm, mocks = self._patches(rcs_value=90)
        with cm:
            main(self._argv())
        mocks["run_mutation_testing"].assert_not_called()

    def test_without_skip_flag_the_real_mutation_runner_is_invoked(self):
        argv = _min_argv(**{"--out": self.out_path, "--min-rcs": "80"})  # no --skip-mutation-testing
        cm, mocks = self._patches(rcs_value=90)
        with cm:
            main(argv)
        mocks["run_mutation_testing"].assert_called_once()


if __name__ == "__main__":
    unittest.main()
