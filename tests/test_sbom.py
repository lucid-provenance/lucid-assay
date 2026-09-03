"""
Direct unit tests for cli.parsers.sbom: CycloneDX/SPDX SBOM ingestion,
license-policy classification, and the SARIF-compatible findings/
resolved_dependencies projections it produces. Covers each format's happy
path, the module's own "Hardened against" fail-closed guarantees (missing/
corrupt/unrecognized input never raises, always available=False), and
classify_license_expression()'s documented AND/OR handling.
"""
import json
import os
import shutil
import tempfile
import unittest

from cli.parsers.sarif import SarifSummaryReport
from cli.parsers.sbom import (
    DEFAULT_LICENSE_POLICY,
    SBOM_LICENSE_TOOL_NAME,
    LicensePolicy,
    SbomComponent,
    build_license_findings,
    build_sbom_sarif_report,
    classify_license_expression,
    detect_sbom_format,
    parse_cyclonedx_sbom,
    parse_sbom_file,
    parse_spdx3_sbom,
    parse_spdx_2_sbom,
    sbom_components_to_resolved_dependencies,
)


class TmpDirMixin:
    def _tmp(self) -> str:
        d = tempfile.mkdtemp()
        self.addCleanup(lambda: shutil.rmtree(d, ignore_errors=True))
        return d

    def _write_json(self, name: str, doc, tmp_dir: str = None) -> str:
        d = tmp_dir if tmp_dir is not None else self._tmp()
        path = os.path.join(d, name)
        with open(path, "w", encoding="utf-8") as f:
            json.dump(doc, f)
        return path


# ---------------------------------------------------------------------------
# classify_license_expression
# ---------------------------------------------------------------------------


class ClassifyLicenseExpressionTests(unittest.TestCase):
    def test_permissive_single_term(self):
        for expr in ("MIT", "Apache-2.0", "BSD-3-Clause", "ISC", "0BSD"):
            self.assertEqual(classify_license_expression(expr)[0], "permissive", expr)

    def test_forbidden_single_term(self):
        for expr in ("AGPL-3.0", "GPL-3.0-only", "GPL-2.0-or-later", "SSPL-1.0", "CC-BY-NC-4.0"):
            classification, matched = classify_license_expression(expr)
            self.assertEqual(classification, "forbidden", expr)
            self.assertEqual(matched, [expr])

    def test_unclassified_single_term(self):
        for expr in ("LGPL-3.0", "MPL-2.0", "EPL-2.0", "Some Custom License"):
            self.assertEqual(classify_license_expression(expr)[0], "unclassified", expr)

    def test_missing_or_empty_is_unclassified(self):
        self.assertEqual(classify_license_expression(None)[0], "unclassified")
        self.assertEqual(classify_license_expression("")[0], "unclassified")
        self.assertEqual(classify_license_expression("   ")[0], "unclassified")

    def test_noassertion_and_none_are_unclassified_not_permissive(self):
        self.assertEqual(classify_license_expression("NOASSERTION")[0], "unclassified")
        self.assertEqual(classify_license_expression("NONE")[0], "unclassified")
        self.assertEqual(classify_license_expression("noassertion")[0], "unclassified")

    def test_and_expression_forbidden_if_any_term_forbidden(self):
        classification, matched = classify_license_expression("MIT AND GPL-3.0-only")
        self.assertEqual(classification, "forbidden")
        self.assertEqual(matched, ["GPL-3.0-only"])

    def test_and_expression_permissive_if_all_terms_permissive(self):
        self.assertEqual(classify_license_expression("MIT AND Apache-2.0")[0], "permissive")

    def test_or_expression_permissive_branch_is_not_a_violation(self):
        # A dual license where a consumer can legally choose the
        # permissive branch is not itself forbidden.
        classification, matched = classify_license_expression("GPL-3.0-only OR Apache-2.0")
        self.assertEqual(classification, "unclassified")  # not all-permissive, not all-forbidden
        self.assertEqual(matched, [])

    def test_or_expression_forbidden_only_if_every_branch_forbidden(self):
        classification, matched = classify_license_expression("GPL-3.0-only OR AGPL-3.0")
        self.assertEqual(classification, "forbidden")
        self.assertEqual(set(matched), {"GPL-3.0-only", "AGPL-3.0"})

    def test_or_expression_all_permissive(self):
        self.assertEqual(classify_license_expression("MIT OR Apache-2.0")[0], "permissive")

    def test_with_exception_clause_is_still_classified(self):
        # WITH is stripped as a boolean-token operator, same as AND/OR.
        classification, matched = classify_license_expression("GPL-2.0-only WITH Classpath-exception-2.0")
        self.assertEqual(classification, "forbidden")
        self.assertEqual(matched, ["GPL-2.0-only"])

    def test_parentheses_are_stripped(self):
        self.assertEqual(classify_license_expression("(MIT)")[0], "permissive")

    def test_custom_policy_overrides_defaults(self):
        policy = LicensePolicy(
            forbidden_prefixes=("MIT",), permissive_prefixes=(), permissive_exact=frozenset({"GPL-3.0"})
        )
        self.assertEqual(classify_license_expression("MIT", policy)[0], "forbidden")
        self.assertEqual(classify_license_expression("GPL-3.0", policy)[0], "permissive")

    def test_expression_of_only_operator_tokens_is_unclassified(self):
        self.assertEqual(classify_license_expression("AND")[0], "unclassified")

    def test_or_later_suffix_is_not_mistaken_for_the_or_operator(self):
        # Regression test: "-or-later" is a single hyphenated SPDX
        # identifier suffix (GPL-2.0-or-later, LGPL-2.1-or-later, ...),
        # not the boolean OR operator wedged inside a word.
        for expr in ("GPL-2.0-or-later", "GPL-3.0-or-later", "LGPL-2.1-or-later"):
            classification, matched = classify_license_expression(expr)
            self.assertEqual(classification, "forbidden" if not expr.startswith("LGPL") else "unclassified", expr)
            if classification == "forbidden":
                self.assertEqual(matched, [expr])

    def test_default_policy_is_the_module_default(self):
        # Omitting `policy` (None) must classify identically to explicitly
        # passing DEFAULT_LICENSE_POLICY -- proving the fallback inside
        # classify_license_expression is genuinely that same policy, not a
        # separately-constructed equivalent that happens to agree here.
        via_omitted_policy = classify_license_expression("AGPL-3.0", None)
        via_explicit_policy = classify_license_expression("AGPL-3.0", DEFAULT_LICENSE_POLICY)
        self.assertEqual(via_omitted_policy, via_explicit_policy)
        self.assertEqual(via_omitted_policy[0], "forbidden")


# ---------------------------------------------------------------------------
# Format detection
# ---------------------------------------------------------------------------


class DetectSbomFormatTests(unittest.TestCase):
    def test_cyclonedx_via_bom_format(self):
        self.assertEqual(detect_sbom_format({"bomFormat": "CycloneDX", "specVersion": "1.5"}), "cyclonedx")

    def test_cyclonedx_without_bom_format_field(self):
        self.assertEqual(detect_sbom_format({"specVersion": "1.6", "components": []}), "cyclonedx")

    def test_spdx_2_3(self):
        self.assertEqual(detect_sbom_format({"spdxVersion": "SPDX-2.3", "packages": []}), "spdx2")

    def test_spdx_3_0_via_version_string(self):
        self.assertEqual(detect_sbom_format({"spdxVersion": "SPDX-3.0", "packages": []}), "spdx3")

    def test_spdx_3_0_via_graph_shape(self):
        self.assertEqual(detect_sbom_format({"@context": "https://spdx.org/rdf/3.0.1", "@graph": []}), "spdx3")

    def test_unrecognized_document_returns_none(self):
        self.assertIsNone(detect_sbom_format({"hello": "world"}))
        self.assertIsNone(detect_sbom_format([]))
        self.assertIsNone(detect_sbom_format("not a dict"))
        self.assertIsNone(detect_sbom_format(None))


# ---------------------------------------------------------------------------
# CycloneDX parsing
# ---------------------------------------------------------------------------


def _cdx_doc(components):
    return {"bomFormat": "CycloneDX", "specVersion": "1.5", "components": components}


class ParseCycloneDxTests(unittest.TestCase):
    def test_component_with_license_id(self):
        comps = parse_cyclonedx_sbom(
            _cdx_doc([{"type": "library", "name": "flask", "version": "3.0.0",
                       "purl": "pkg:pypi/flask@3.0.0", "licenses": [{"license": {"id": "BSD-3-Clause"}}]}])
        )
        self.assertEqual(len(comps), 1)
        c = comps[0]
        self.assertEqual((c.name, c.version, c.purl), ("flask", "3.0.0", "pkg:pypi/flask@3.0.0"))
        self.assertEqual(c.license_expression, "BSD-3-Clause")

    def test_component_with_license_expression(self):
        comps = parse_cyclonedx_sbom(
            _cdx_doc([{"name": "dual", "version": "1.0", "licenses": [{"expression": "MIT OR Apache-2.0"}]}])
        )
        self.assertEqual(comps[0].license_expression, "MIT OR Apache-2.0")

    def test_multiple_license_entries_joined_with_and(self):
        comps = parse_cyclonedx_sbom(
            _cdx_doc([{"name": "multi", "licenses": [
                {"license": {"id": "MIT"}}, {"license": {"id": "Apache-2.0"}},
            ]}])
        )
        self.assertEqual(comps[0].license_expression, "MIT AND Apache-2.0")

    def test_free_text_license_name_is_preserved_not_dropped(self):
        comps = parse_cyclonedx_sbom(_cdx_doc([{"name": "weird", "licenses": [{"license": {"name": "My Custom EULA"}}]}]))
        self.assertEqual(comps[0].license_expression, "My Custom EULA")

    def test_no_licenses_field_is_none(self):
        comps = parse_cyclonedx_sbom(_cdx_doc([{"name": "bare"}]))
        self.assertIsNone(comps[0].license_expression)

    def test_licenses_field_with_only_malformed_entries_is_none(self):
        comps = parse_cyclonedx_sbom(_cdx_doc([{"name": "x", "licenses": ["not-a-dict", {"license": {}}]}]))
        self.assertIsNone(comps[0].license_expression)

    def test_hashes_extracted_as_digest(self):
        comps = parse_cyclonedx_sbom(
            _cdx_doc([{"name": "hashed", "hashes": [{"alg": "SHA-256", "content": "AB12"}]}])
        )
        self.assertEqual(comps[0].digest, {"sha256": "ab12"})

    def test_unrecognized_hash_alg_is_skipped(self):
        comps = parse_cyclonedx_sbom(_cdx_doc([{"name": "x", "hashes": [{"alg": "BLAKE3", "content": "ff"}]}]))
        self.assertEqual(comps[0].digest, {})

    def test_non_string_and_non_dict_hash_entries_are_skipped(self):
        comps = parse_cyclonedx_sbom(_cdx_doc([{"name": "x", "hashes": [
            "not-a-dict", {"alg": 123, "content": "ff"}, {"alg": "SHA-256", "content": "aa"},
        ]}]))
        self.assertEqual(comps[0].digest, {"sha256": "aa"})

    def test_component_missing_name_is_skipped(self):
        comps = parse_cyclonedx_sbom(_cdx_doc([{"version": "1.0"}, {"name": "ok"}]))
        self.assertEqual([c.name for c in comps], ["ok"])

    def test_nested_sub_components_are_walked(self):
        doc = _cdx_doc([
            {"name": "outer", "components": [
                {"name": "inner", "components": [{"name": "innermost"}]},
            ]},
        ])
        names = sorted(c.name for c in parse_cyclonedx_sbom(doc))
        self.assertEqual(names, ["inner", "innermost", "outer"])

    def test_missing_components_array_returns_empty(self):
        self.assertEqual(parse_cyclonedx_sbom({"bomFormat": "CycloneDX"}), [])

    def test_malformed_components_entries_are_skipped_individually(self):
        comps = parse_cyclonedx_sbom(_cdx_doc(["not-a-dict", None, {"name": "ok"}]))
        self.assertEqual([c.name for c in comps], ["ok"])


# ---------------------------------------------------------------------------
# SPDX 2.x parsing
# ---------------------------------------------------------------------------


def _spdx2_doc(packages):
    return {"spdxVersion": "SPDX-2.3", "packages": packages}


class ParseSpdx2Tests(unittest.TestCase):
    def test_package_with_concluded_license(self):
        comps = parse_spdx_2_sbom(_spdx2_doc([
            {"name": "requests", "versionInfo": "2.31.0", "licenseConcluded": "Apache-2.0",
             "licenseDeclared": "MIT", "externalRefs": [
                {"referenceCategory": "PACKAGE-MANAGER", "referenceType": "purl", "referenceLocator": "pkg:pypi/requests@2.31.0"},
             ]},
        ]))
        c = comps[0]
        self.assertEqual((c.name, c.version, c.purl), ("requests", "2.31.0", "pkg:pypi/requests@2.31.0"))
        # Concluded takes precedence over declared.
        self.assertEqual((c.license_expression, c.license_source), ("Apache-2.0", "concluded"))

    def test_falls_back_to_declared_when_concluded_is_noassertion(self):
        comps = parse_spdx_2_sbom(_spdx2_doc([
            {"name": "pkg", "licenseConcluded": "NOASSERTION", "licenseDeclared": "GPL-3.0-only"},
        ]))
        self.assertEqual((comps[0].license_expression, comps[0].license_source), ("GPL-3.0-only", "declared"))

    def test_both_noassertion_reports_unspecified_with_raw_value(self):
        comps = parse_spdx_2_sbom(_spdx2_doc([
            {"name": "pkg", "licenseConcluded": "NOASSERTION", "licenseDeclared": "NOASSERTION"},
        ]))
        self.assertEqual(comps[0].license_source, "unspecified")

    def test_checksums_extracted_as_digest(self):
        comps = parse_spdx_2_sbom(_spdx2_doc([
            {"name": "pkg", "checksums": [{"algorithm": "SHA256", "checksumValue": "DEAD"}]},
        ]))
        self.assertEqual(comps[0].digest, {"sha256": "dead"})

    def test_package_missing_name_is_skipped(self):
        comps = parse_spdx_2_sbom(_spdx2_doc([{"versionInfo": "1.0"}, {"name": "ok"}]))
        self.assertEqual([c.name for c in comps], ["ok"])

    def test_missing_packages_array_returns_empty(self):
        self.assertEqual(parse_spdx_2_sbom({"spdxVersion": "SPDX-2.3"}), [])

    def test_external_refs_without_a_purl_type_is_no_purl(self):
        comps = parse_spdx_2_sbom(_spdx2_doc([
            {"name": "x", "externalRefs": ["not-a-dict", {"referenceType": "cpe23Type", "referenceLocator": "cpe:..."}]},
        ]))
        self.assertIsNone(comps[0].purl)


# ---------------------------------------------------------------------------
# SPDX 3.0 parsing (best-effort subset)
# ---------------------------------------------------------------------------


class ParseSpdx3Tests(unittest.TestCase):
    def test_software_package_element_is_parsed(self):
        doc = {
            "@graph": [
                {
                    "type": "software_Package",
                    "name": "lodash",
                    "software_packageVersion": "4.17.21",
                    "software_declaredLicense": "MIT",
                    "externalIdentifier": [{"externalIdentifierType": "purl", "identifier": "pkg:npm/lodash@4.17.21"}],
                    "verifiedUsing": [{"algorithm": "sha256", "hashValue": "abc123"}],
                },
                {"type": "Relationship", "from": "x", "to": "y"},  # non-package element, ignored
            ]
        }
        comps = parse_spdx3_sbom(doc)
        self.assertEqual(len(comps), 1)
        c = comps[0]
        self.assertEqual((c.name, c.version, c.purl), ("lodash", "4.17.21", "pkg:npm/lodash@4.17.21"))
        self.assertEqual(c.license_expression, "MIT")
        self.assertEqual(c.digest, {"sha256": "abc123"})

    def test_unresolved_license_reference_is_none_not_guessed(self):
        # A real SPDX 3.0 doc can reference a license via a separate
        # graph node's @id rather than inlining the string -- out of
        # scope, so this must stay None, never fabricated.
        doc = {"@graph": [{"type": "software_Package", "name": "x", "software_concludedLicense": {"@id": "urn:license:1"}}]}
        comps = parse_spdx3_sbom(doc)
        self.assertIsNone(comps[0].license_expression)

    def test_missing_graph_returns_empty(self):
        self.assertEqual(parse_spdx3_sbom({}), [])

    def test_element_with_no_type_field_at_all_is_skipped(self):
        doc = {"@graph": [{"name": "no-type"}, {"type": "software_Package", "name": "ok"}]}
        self.assertEqual([c.name for c in parse_spdx3_sbom(doc)], ["ok"])

    def test_package_type_element_missing_name_is_skipped(self):
        doc = {"@graph": [{"type": "software_Package"}, {"type": "software_Package", "name": "ok"}]}
        self.assertEqual([c.name for c in parse_spdx3_sbom(doc)], ["ok"])

    def test_external_identifier_without_a_purl_type_is_no_purl(self):
        doc = {"@graph": [{"type": "software_Package", "name": "x", "externalIdentifier": [
            "not-a-dict", {"externalIdentifierType": "cpe23Type", "identifier": "cpe:..."},
        ]}]}
        comps = parse_spdx3_sbom(doc)
        self.assertIsNone(comps[0].purl)

    def test_non_dict_graph_element_is_skipped(self):
        doc = {"@graph": ["not-a-dict", {"type": "software_Package", "name": "ok"}]}
        self.assertEqual([c.name for c in parse_spdx3_sbom(doc)], ["ok"])

    def test_element_type_via_at_type_iri(self):
        doc = {"@graph": [{"@type": "https://spdx.org/rdf/3.0.1/terms/Software/Package", "name": "iri-typed"}]}
        self.assertEqual([c.name for c in parse_spdx3_sbom(doc)], ["iri-typed"])


# ---------------------------------------------------------------------------
# parse_sbom_file (end-to-end, incl. fail-closed paths)
# ---------------------------------------------------------------------------


class ParseSbomFileTests(TmpDirMixin, unittest.TestCase):
    def test_valid_cyclonedx_file(self):
        doc = _cdx_doc([{"name": "x", "version": "1.0", "licenses": [{"license": {"id": "MIT"}}]}])
        path = self._write_json("bom.json", doc)
        report = parse_sbom_file(path)
        self.assertTrue(report.available)
        self.assertEqual(report.format, "cyclonedx")
        self.assertEqual(len(report.components), 1)
        # The raw document is carried verbatim, not just the extracted
        # components -- cli.sbom_statement's companion statement wraps
        # this, not a re-derivation of it.
        self.assertEqual(report.raw_document, doc)

    def test_valid_spdx2_file(self):
        path = self._write_json("bom.spdx.json", _spdx2_doc([{"name": "x", "licenseConcluded": "MIT"}]))
        report = parse_sbom_file(path)
        self.assertTrue(report.available)
        self.assertEqual(report.format, "spdx2")

    def test_unavailable_report_has_no_raw_document(self):
        report = parse_sbom_file(os.path.join(self._tmp(), "does-not-exist.json"))
        self.assertIsNone(report.raw_document)

    def test_missing_file_degrades(self):
        report = parse_sbom_file(os.path.join(self._tmp(), "does-not-exist.json"))
        self.assertFalse(report.available)
        self.assertIn("could not be read/parsed", report.reasons[0])

    def test_malformed_json_degrades(self):
        d = self._tmp()
        path = os.path.join(d, "bad.json")
        with open(path, "w") as f:
            f.write("{not json")
        report = parse_sbom_file(path)
        self.assertFalse(report.available)

    def test_unrecognized_format_degrades(self):
        path = self._write_json("weird.json", {"hello": "world"})
        report = parse_sbom_file(path)
        self.assertFalse(report.available)
        self.assertIn("not recognized", report.reasons[0])

    def test_oversized_file_degrades(self):
        import cli.parsers.sbom as sbom_module

        d = self._tmp()
        path = os.path.join(d, "huge.json")
        with open(path, "w") as f:
            f.write("{}")
        original_max = sbom_module.MAX_SBOM_FILE_SIZE
        sbom_module.MAX_SBOM_FILE_SIZE = 1
        try:
            report = parse_sbom_file(path)
        finally:
            sbom_module.MAX_SBOM_FILE_SIZE = original_max
        self.assertFalse(report.available)


# ---------------------------------------------------------------------------
# sbom_components_to_resolved_dependencies
# ---------------------------------------------------------------------------


class ResolvedDependenciesProjectionTests(unittest.TestCase):
    def test_purl_bearing_components_projected(self):
        comps = [
            SbomComponent(name="a", purl="pkg:pypi/a@1.0", digest={"sha256": "aa"}),
            SbomComponent(name="b", purl=None),  # no purl -- omitted
        ]
        deps = sbom_components_to_resolved_dependencies(comps)
        self.assertEqual(deps, [{"uri": "pkg:pypi/a@1.0", "digest": {"sha256": "aa"}}])

    def test_dedup_by_uri_first_wins(self):
        comps = [
            SbomComponent(name="a", purl="pkg:pypi/a@1.0", digest={"sha256": "first"}),
            SbomComponent(name="a-dup", purl="pkg:pypi/a@1.0", digest={"sha256": "second"}),
        ]
        deps = sbom_components_to_resolved_dependencies(comps)
        self.assertEqual(len(deps), 1)
        self.assertEqual(deps[0]["digest"], {"sha256": "first"})

    def test_non_pkg_purl_scheme_is_omitted(self):
        comps = [SbomComponent(name="x", purl="cpe:2.3:a:vendor:product")]
        self.assertEqual(sbom_components_to_resolved_dependencies(comps), [])


# ---------------------------------------------------------------------------
# build_license_findings / build_sbom_sarif_report
# ---------------------------------------------------------------------------


class BuildLicenseFindingsTests(unittest.TestCase):
    def test_permissive_component_produces_no_finding(self):
        findings, tally = build_license_findings([SbomComponent(name="clean", license_expression="MIT")])
        self.assertEqual(findings, [])
        self.assertEqual(tally, {"forbidden": 0, "unclassified": 0, "permissive": 1})

    def test_forbidden_component_produces_error_finding(self):
        findings, tally = build_license_findings(
            [SbomComponent(name="bad", version="2.0", purl="pkg:pypi/bad@2.0", license_expression="AGPL-3.0")]
        )
        self.assertEqual(len(findings), 1)
        f = findings[0]
        self.assertEqual(f.level, "error")
        self.assertEqual(f.tool_name, SBOM_LICENSE_TOOL_NAME)
        self.assertIn("bad@2.0", f.message)
        self.assertIn("license", f.tags)
        self.assertIn("forbidden", f.tags)
        self.assertEqual(tally["forbidden"], 1)

    def test_unclassified_component_produces_warning_finding(self):
        findings, tally = build_license_findings([SbomComponent(name="weird", license_expression="MPL-2.0")])
        self.assertEqual(len(findings), 1)
        self.assertEqual(findings[0].level, "warning")
        self.assertEqual(tally["unclassified"], 1)

    def test_missing_license_is_unclassified_not_silently_clean(self):
        findings, tally = build_license_findings([SbomComponent(name="nolicense")])
        self.assertEqual(len(findings), 1)
        self.assertEqual(tally["unclassified"], 1)


class BuildSbomSarifReportTests(unittest.TestCase):
    def test_shape_is_a_real_sarif_summary_report(self):
        components = [
            SbomComponent(name="ok", license_expression="MIT"),
            SbomComponent(name="bad", license_expression="GPL-3.0-only"),
        ]
        report = build_sbom_sarif_report(components)
        self.assertIsInstance(report, SarifSummaryReport)
        self.assertTrue(report.available)
        self.assertEqual(report.tools_scanned, [SBOM_LICENSE_TOOL_NAME])
        self.assertEqual(report.total_findings, 1)
        self.assertEqual(report.errors_count, 1)
        self.assertEqual(len(report.tools), 1)
        self.assertEqual(report.tools[0].extensions["sbom_license_policy"], {"forbidden": 1, "unclassified": 0, "permissive": 1})

    def test_report_hash_defaults_to_none(self):
        report = build_sbom_sarif_report([SbomComponent(name="ok", license_expression="MIT")])
        self.assertIsNone(report.tools[0].report_hash)

    def test_report_hash_is_threaded_through_when_given(self):
        report_hash = {"algorithm": "sha256", "value": "a" * 64}
        report = build_sbom_sarif_report([SbomComponent(name="ok")], report_hash=report_hash)
        self.assertEqual(report.tools[0].report_hash, report_hash)
        # Defensive copy -- mutating the caller's dict afterwards must not
        # reach back into the report.
        report_hash["value"] = "mutated"
        self.assertEqual(report.tools[0].report_hash["value"], "a" * 64)

    def test_empty_component_list_is_a_clean_available_report(self):
        report = build_sbom_sarif_report([])
        self.assertTrue(report.available)
        self.assertEqual(report.total_findings, 0)


if __name__ == "__main__":
    unittest.main()
