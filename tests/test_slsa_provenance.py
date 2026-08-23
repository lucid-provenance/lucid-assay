"""
Tests for cli/slsa_provenance.py's genuine SLSA v1.0 provenance builder.

Two things are covered:
  1. Ground-truth-only behavior: fields populate from real ambient
     GITHUB_*/RUNNER_ENVIRONMENT env vars when present, and are simply
     absent (never a fabricated placeholder) when they aren't -- including
     the hosted-builder claim only firing for a genuinely GitHub-hosted
     runner.
  2. That a fully-populated statement (as a real GitHub-hosted Actions run
     would produce) legitimately satisfies cli/verify.py's SLSA Build
     Level 1/2 checklist -- the two modules must agree on what "SLSA
     provenance shaped" means.
"""
from __future__ import annotations

import json
import os
import unittest

from cli.slsa_provenance import (
    GITHUB_ACTIONS_WORKFLOW_BUILD_TYPE,
    GITHUB_HOSTED_BUILDER_ID,
    SLSA_PROVENANCE_PREDICATE_TYPE,
    build_slsa_provenance_statement,
)
from cli.verify import _evaluate_slsa_l1, _evaluate_slsa_l2

_FIXTURE_PATH = os.path.join(os.path.dirname(os.path.abspath(__file__)), "fixtures", "slsa_provenance_statement.output.json")

_GITHUB_ENV_KEYS = (
    "GITHUB_REPOSITORY",
    "GITHUB_SERVER_URL",
    "GITHUB_SHA",
    "GITHUB_RUN_ID",
    "GITHUB_RUN_ATTEMPT",
    "GITHUB_WORKFLOW_REF",
    "RUNNER_ENVIRONMENT",
)


class _EnvIsolatedTestCase(unittest.TestCase):
    """Clears every GITHUB_*/RUNNER_ENVIRONMENT var this module reads
    before each test and restores the original environment after, so
    these tests are deterministic whether or not they happen to run
    inside real CI (where most of these vars really are set)."""

    def setUp(self):
        self._saved = {k: os.environ.get(k) for k in _GITHUB_ENV_KEYS}
        for k in _GITHUB_ENV_KEYS:
            os.environ.pop(k, None)

    def tearDown(self):
        for k, v in self._saved.items():
            if v is None:
                os.environ.pop(k, None)
            else:
                os.environ[k] = v

    def _set_hosted_github_actions_env(self):
        os.environ["GITHUB_REPOSITORY"] = "org/svc"
        os.environ["GITHUB_SERVER_URL"] = "https://github.com"
        os.environ["GITHUB_SHA"] = "b" * 40
        os.environ["GITHUB_RUN_ID"] = "123456"
        os.environ["GITHUB_RUN_ATTEMPT"] = "1"
        os.environ["GITHUB_WORKFLOW_REF"] = "org/svc/.github/workflows/assay.yml@refs/heads/main"
        os.environ["RUNNER_ENVIRONMENT"] = "github-hosted"


class OffCiFailsClosedTests(_EnvIsolatedTestCase):
    def test_off_ci_omits_every_ambient_field(self):
        statement = build_slsa_provenance_statement(
            subject_name="registry.example.com/org/svc",
            subject_sha256="a" * 64,
            started_at="2026-08-23T12:00:00Z",
            finished_at="2026-08-23T12:00:42Z",
        )
        self.assertEqual(statement["predicateType"], SLSA_PROVENANCE_PREDICATE_TYPE)
        build_definition = statement["predicate"]["buildDefinition"]
        self.assertEqual(build_definition["externalParameters"], {})
        self.assertEqual(build_definition["resolvedDependencies"], [])
        self.assertNotIn("id", statement["predicate"]["runDetails"]["builder"])
        self.assertNotIn("invocationId", statement["predicate"]["runDetails"]["metadata"])

    def test_self_hosted_runner_never_claims_hosted_builder_id(self):
        self._set_hosted_github_actions_env()
        os.environ["RUNNER_ENVIRONMENT"] = "self-hosted"
        statement = build_slsa_provenance_statement(
            subject_name="registry.example.com/org/svc",
            subject_sha256="a" * 64,
            started_at="2026-08-23T12:00:00Z",
        )
        self.assertNotIn("id", statement["predicate"]["runDetails"]["builder"])

    def test_malformed_workflow_ref_without_at_sign_is_omitted_not_guessed(self):
        self._set_hosted_github_actions_env()
        os.environ["GITHUB_WORKFLOW_REF"] = "org/svc/.github/workflows/assay.yml"  # no "@ref"
        statement = build_slsa_provenance_statement(
            subject_name="registry.example.com/org/svc",
            subject_sha256="a" * 64,
            started_at="2026-08-23T12:00:00Z",
        )
        self.assertEqual(statement["predicate"]["buildDefinition"]["externalParameters"], {})


class GenuineGitHubActionsRunTests(_EnvIsolatedTestCase):
    def test_matches_fixture_statement(self):
        self._set_hosted_github_actions_env()
        statement = build_slsa_provenance_statement(
            subject_name="registry.example.com/org/svc",
            subject_sha256="a" * 64,
            started_at="2026-08-23T12:00:00Z",
            finished_at="2026-08-23T12:00:42Z",
            resolved_dependencies=[
                {"uri": "pkg:pypi/requests@2.31.0", "digest": {"sha256": "c" * 64}},
                {"uri": "", "digest": {"sha256": "d" * 64}},  # dropped: no usable uri
                "not-a-dict",  # dropped: not even a dict
            ],
        )
        with open(_FIXTURE_PATH, "r", encoding="utf-8") as f:
            expected = json.load(f)
        self.assertEqual(statement, expected)

    def test_build_type_is_the_real_slsa_github_actions_buildtype(self):
        self.assertEqual(
            GITHUB_ACTIONS_WORKFLOW_BUILD_TYPE,
            "https://slsa-framework.github.io/github-actions-buildtypes/workflow/v1",
        )

    def test_satisfies_verify_py_slsa_build_level_1_and_2_checklists(self):
        """The whole point of this module: a genuinely-populated statement
        must legitimately pass cli/verify.py's informational SLSA
        checklist, not just superficially resemble the schema."""
        self._set_hosted_github_actions_env()
        statement = build_slsa_provenance_statement(
            subject_name="registry.example.com/org/svc",
            subject_sha256="a" * 64,
            started_at="2026-08-23T12:00:00Z",
            finished_at="2026-08-23T12:00:42Z",
        )

        level1 = _evaluate_slsa_l1(statement)
        self.assertTrue(level1["passed"], level1["items"])

        level2 = _evaluate_slsa_l2(
            statement,
            identity_status="verified",
            identity_detail="",
            expected_repository=None,
        )
        self.assertTrue(level2["passed"], level2["items"])
        hosted_builder_item = next(i for i in level2["items"] if i["label"].startswith("Hosted Builder Identity"))
        self.assertIn(GITHUB_HOSTED_BUILDER_ID, hosted_builder_item["label"])


if __name__ == "__main__":
    unittest.main()
