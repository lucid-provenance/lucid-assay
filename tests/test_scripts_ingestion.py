import json
import os
import sys
import tempfile
import unittest
from pathlib import Path

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from scripts._ingestion_lib import (
    STATUS_AUDIT,
    STATUS_FAIL,
    STATUS_PASS,
    compute_denylist_digest,
    evaluate_enf2_curated_feeds,
    evaluate_feed_provenance,
    evaluate_ing2_local_copies,
    evaluate_ing3_denylists,
    load_denylist,
    run_ingestion_checks,
)
from scripts.verify_ingestion import _resolve_internal_hosts, main as verify_main
from scripts.emit_s2c2f_evidence import build_predicate, build_statement
from scripts.emit_s2c2f_evidence import main as emit_main


def _write_denylist(path: Path, entries):
    doc = {"schema_version": "s2c2f-denylist/v1", "entries": entries, "digest_sha256": compute_denylist_digest(entries)}
    path.write_text(json.dumps(doc))
    return doc


class DenylistTests(unittest.TestCase):
    def test_missing_file_fails_closed_to_audit_not_pass(self):
        doc, error = load_denylist(Path("/nonexistent/denylist.json"))
        self.assertIsNone(doc)
        self.assertIn("no denylist policy artifact found", error)

    def test_valid_empty_denylist_loads(self):
        with tempfile.TemporaryDirectory() as tmp:
            path = Path(tmp) / "denylist.json"
            _write_denylist(path, [])
            doc, error = load_denylist(path)
            self.assertIsNone(error)
            self.assertEqual(doc["entries"], [])

    def test_tampered_digest_fails_closed(self):
        with tempfile.TemporaryDirectory() as tmp:
            path = Path(tmp) / "denylist.json"
            doc = _write_denylist(path, [{"ecosystem": "pypi", "name": "evil-pkg", "reason": "test"}])
            doc["digest_sha256"] = "0" * 64
            path.write_text(json.dumps(doc))
            loaded, error = load_denylist(path)
            self.assertIsNone(loaded)
            self.assertIn("does not match its own entries", error)

    def test_malformed_entry_missing_reason_fails_closed(self):
        with tempfile.TemporaryDirectory() as tmp:
            path = Path(tmp) / "denylist.json"
            entries = [{"ecosystem": "pypi", "name": "x"}]  # no 'reason'
            path.write_text(json.dumps({"schema_version": "s2c2f-denylist/v1", "entries": entries, "digest_sha256": compute_denylist_digest(entries)}))
            doc, error = load_denylist(path)
            self.assertIsNone(doc)
            self.assertIn("required", error)

    def test_ing3_pass_when_no_resolved_dependency_matches(self):
        with tempfile.TemporaryDirectory() as tmp:
            path = Path(tmp) / "denylist.json"
            _write_denylist(path, [{"ecosystem": "pypi", "name": "evil-pkg", "reason": "test"}])
            result = evaluate_ing3_denylists(path, [{"uri": "pkg:pypi/requests@2.31.0", "digest": {}}])
            self.assertEqual(result.status, STATUS_PASS)

    def test_ing3_fails_when_resolved_dependency_matches_denylist(self):
        with tempfile.TemporaryDirectory() as tmp:
            path = Path(tmp) / "denylist.json"
            _write_denylist(path, [{"ecosystem": "pypi", "name": "evil-pkg", "reason": "test"}])
            result = evaluate_ing3_denylists(path, [{"uri": "pkg:pypi/evil-pkg@1.0.0", "digest": {}}])
            self.assertEqual(result.status, STATUS_FAIL)
            self.assertIn("evil-pkg", result.detail)


class FeedProvenanceTests(unittest.TestCase):
    def test_npm_all_public_fails(self):
        with tempfile.TemporaryDirectory() as tmp:
            repo = Path(tmp)
            (repo / "package-lock.json").write_text(json.dumps({
                "packages": {
                    "": {},
                    "node_modules/left-pad": {"resolved": "https://registry.npmjs.org/left-pad/-/left-pad-1.3.0.tgz"},
                }
            }))
            results = evaluate_feed_provenance(repo, internal_hosts=["artifactory.internal.example"])
            self.assertEqual(len(results), 1)
            self.assertEqual(results[0].status, STATUS_FAIL)

    def test_npm_all_internal_passes(self):
        with tempfile.TemporaryDirectory() as tmp:
            repo = Path(tmp)
            (repo / "package-lock.json").write_text(json.dumps({
                "packages": {
                    "": {},
                    "node_modules/left-pad": {"resolved": "https://artifactory.internal.example/npm/left-pad/-/left-pad-1.3.0.tgz"},
                }
            }))
            results = evaluate_feed_provenance(repo, internal_hosts=["artifactory.internal.example"])
            self.assertEqual(results[0].status, STATUS_PASS)

    def test_no_manifests_at_all_yields_empty_results_not_a_fabricated_status(self):
        with tempfile.TemporaryDirectory() as tmp:
            results = evaluate_feed_provenance(Path(tmp), internal_hosts=[])
            self.assertEqual(results, [])
            # ING-2/ENF-2 must both degrade to AUDIT, never PASS/FAIL, when
            # there's nothing in the repo to evaluate at all.
            self.assertEqual(evaluate_ing2_local_copies(results).status, STATUS_AUDIT)
            self.assertEqual(evaluate_enf2_curated_feeds(results).status, STATUS_AUDIT)

    def test_pip_manifest_present_without_internal_config_fails(self):
        with tempfile.TemporaryDirectory() as tmp:
            repo = Path(tmp)
            (repo / "requirements.txt").write_text("requests==2.31.0\n")
            results = evaluate_feed_provenance(repo, internal_hosts=["proxy.internal.example"])
            self.assertEqual(len(results), 1)
            self.assertEqual(results[0].ecosystem, "pip")
            self.assertEqual(results[0].status, STATUS_FAIL)

    def test_pip_manifest_present_with_internal_pip_conf_passes(self):
        with tempfile.TemporaryDirectory() as tmp:
            repo = Path(tmp)
            (repo / "requirements.txt").write_text("requests==2.31.0\n")
            (repo / "pip.conf").write_text("[global]\nindex-url = https://proxy.internal.example/simple\n")
            results = evaluate_feed_provenance(repo, internal_hosts=["proxy.internal.example"])
            self.assertEqual(results[0].status, STATUS_PASS)


class RunIngestionChecksTests(unittest.TestCase):
    def test_unresolvable_repo_dir_degrades_every_control_to_audit(self):
        results = run_ingestion_checks(
            repo_dir=Path("/definitely/does/not/exist"), internal_hosts=[], denylist_path=Path("/nonexistent/denylist.json"), resolved_dependencies=[],
        )
        self.assertEqual({r.status for r in results.values()}, {STATUS_AUDIT})

    def test_full_run_against_a_real_repo_layout(self):
        with tempfile.TemporaryDirectory() as tmp:
            repo = Path(tmp)
            denylist_path = repo / "denylist.json"
            _write_denylist(denylist_path, [])
            (repo / "package-lock.json").write_text(json.dumps({
                "packages": {"": {}, "node_modules/foo": {"resolved": "https://registry.npmjs.org/foo/-/foo-1.0.0.tgz"}}
            }))
            results = run_ingestion_checks(repo_dir=repo, internal_hosts=[], denylist_path=denylist_path, resolved_dependencies=[])
            self.assertEqual(results["ING-3"].status, STATUS_PASS)  # empty denylist, nothing can match
            self.assertEqual(results["ING-2"].status, STATUS_FAIL)  # resolves straight from the public registry
            self.assertEqual(results["ENF-2"].status, STATUS_FAIL)


class VerifyIngestionCliTests(unittest.TestCase):
    def test_resolve_internal_hosts_splits_and_lowercases(self):
        self.assertEqual(_resolve_internal_hosts("Foo.Internal, bar.internal"), ["foo.internal", "bar.internal"])

    def test_resolve_internal_hosts_empty_when_unset(self):
        self.assertEqual(_resolve_internal_hosts(""), [])

    def test_main_exits_nonzero_on_violation_in_enforce_mode(self):
        with tempfile.TemporaryDirectory() as tmp:
            repo = Path(tmp)
            _write_denylist(repo / "denylist.json", [])
            (repo / "requirements.txt").write_text("requests==2.31.0\n")
            exit_code = verify_main(["--repo-dir", str(repo), "--denylist", str(repo / "denylist.json")])
            self.assertEqual(exit_code, 1)

    def test_main_exits_zero_in_audit_only_mode_despite_violation(self):
        with tempfile.TemporaryDirectory() as tmp:
            repo = Path(tmp)
            _write_denylist(repo / "denylist.json", [])
            (repo / "requirements.txt").write_text("requests==2.31.0\n")
            exit_code = verify_main(["--repo-dir", str(repo), "--denylist", str(repo / "denylist.json"), "--audit-only"])
            self.assertEqual(exit_code, 0)

    def test_write_denylist_digest_repairs_a_tampered_file(self):
        with tempfile.TemporaryDirectory() as tmp:
            path = Path(tmp) / "denylist.json"
            doc = _write_denylist(path, [{"ecosystem": "pypi", "name": "evil-pkg", "reason": "test"}])
            doc["digest_sha256"] = "deadbeef"
            path.write_text(json.dumps(doc))
            exit_code = verify_main(["--write-denylist-digest", str(path)])
            self.assertEqual(exit_code, 0)
            loaded, error = load_denylist(path)
            self.assertIsNone(error)
            self.assertEqual(loaded["digest_sha256"], compute_denylist_digest(loaded["entries"]))


def _init_real_git_repo(repo: Path) -> None:
    """A real git repo with one commit -- so build_statement's subject
    carries genuine, deterministic gitCommit/gitTree digests rather than a
    mocked stand-in for them."""
    import subprocess

    subprocess.run(["git", "init", "-q"], cwd=repo, check=True)
    subprocess.run(["git", "config", "user.email", "test@example.com"], cwd=repo, check=True)
    subprocess.run(["git", "config", "user.name", "Test"], cwd=repo, check=True)
    (repo / "README.md").write_text("test\n")
    subprocess.run(["git", "add", "."], cwd=repo, check=True)
    subprocess.run(["git", "commit", "-q", "-m", "init"], cwd=repo, check=True)


class EmitS2C2FEvidenceTests(unittest.TestCase):
    def test_build_predicate_matches_schema_shape(self):
        with tempfile.TemporaryDirectory() as tmp:
            repo = Path(tmp)
            _write_denylist(repo / "denylist.json", [])
            predicate = build_predicate(repo, repo / "denylist.json", [])
            self.assertEqual(predicate["schema_version"], "s2c2f-evidence/v1")
            self.assertEqual(set(predicate["controls"].keys()), {"ING-3", "ING-2", "ENF-2"})
            self.assertIn("would_enforce_exit_code", predicate)

    def test_build_statement_none_without_a_resolvable_commit(self):
        with tempfile.TemporaryDirectory() as tmp:
            repo = Path(tmp)  # not a git repo at all
            _write_denylist(repo / "denylist.json", [])
            predicate = build_predicate(repo, repo / "denylist.json", [])
            self.assertIsNone(predicate["environment"]["git_commit_sha"])
            self.assertIsNone(build_statement(repo, predicate))

    def test_build_statement_carries_real_git_subject(self):
        with tempfile.TemporaryDirectory() as tmp:
            repo = Path(tmp)
            _init_real_git_repo(repo)
            _write_denylist(repo / "denylist.json", [])
            predicate = build_predicate(repo, repo / "denylist.json", [])
            statement = build_statement(repo, predicate)
            self.assertEqual(statement["_type"], "https://in-toto.io/Statement/v1")
            self.assertEqual(statement["predicateType"], "https://lucidprovenance.io/attestations/s2c2f-evidence/v1")
            self.assertIs(statement["predicate"], predicate)
            digests = [s["digest"] for s in statement["subject"]]
            self.assertTrue(any("gitCommit" in d for d in digests))
            self.assertTrue(any("gitTree" in d for d in digests))
            # Real, non-fabricated 40-hex-char git object ids, not placeholders.
            for d in digests:
                for value in d.values():
                    self.assertRegex(value, r"^[0-9a-f]{40}$")

    def test_main_dry_run_sign_writes_a_real_dsse_envelope(self):
        with tempfile.TemporaryDirectory() as tmp:
            repo = Path(tmp)
            _init_real_git_repo(repo)
            _write_denylist(repo / "denylist.json", [])
            out_path = repo / "s2c2f-evidence.unsigned.json"
            exit_code = emit_main(["--repo-dir", str(repo), "--denylist", str(repo / "denylist.json"), "--out", str(out_path), "--dry-run-sign"])
            self.assertEqual(exit_code, 0)
            dsse_path = repo / "s2c2f-evidence.dsse.json"
            self.assertTrue(dsse_path.is_file())
            envelope = json.loads(dsse_path.read_text())
            self.assertEqual(envelope["payloadType"], "application/vnd.in-toto+json")
            import base64
            statement = json.loads(base64.b64decode(envelope["payload"]))
            self.assertEqual(statement["predicateType"], "https://lucidprovenance.io/attestations/s2c2f-evidence/v1")

    def test_main_never_fails_when_sign_requested_without_ambient_credentials(self):
        with tempfile.TemporaryDirectory() as tmp:
            repo = Path(tmp)
            _init_real_git_repo(repo)
            _write_denylist(repo / "denylist.json", [])
            out_path = repo / "s2c2f-evidence.unsigned.json"
            # No ambient OIDC env vars set in this test process -- --sign
            # must degrade to "unsigned only", never raise/exit non-zero.
            exit_code = emit_main(["--repo-dir", str(repo), "--denylist", str(repo / "denylist.json"), "--out", str(out_path), "--sign"])
            self.assertEqual(exit_code, 0)
            self.assertTrue(out_path.is_file())
            self.assertFalse((repo / "s2c2f-evidence.dsse.json").is_file())


if __name__ == "__main__":
    unittest.main()
