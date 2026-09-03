"""
Direct unit tests for cli.sbom_statement: the --sbom companion in-toto
Statement builder (predicateType https://cyclonedx.org/bom /
https://spdx.dev/Document), wrapping a --sbom input's own raw document
verbatim as its predicate.
"""
import unittest

from cli.sbom_statement import (
    CYCLONEDX_PREDICATE_TYPE,
    SPDX_PREDICATE_TYPE,
    STATEMENT_TYPE,
    build_sbom_statement,
    predicate_type_for_format,
)


class PredicateTypeForFormatTests(unittest.TestCase):
    def test_cyclonedx(self):
        self.assertEqual(predicate_type_for_format("cyclonedx"), CYCLONEDX_PREDICATE_TYPE)

    def test_spdx2_and_spdx3_share_one_predicate_type(self):
        self.assertEqual(predicate_type_for_format("spdx2"), SPDX_PREDICATE_TYPE)
        self.assertEqual(predicate_type_for_format("spdx3"), SPDX_PREDICATE_TYPE)

    def test_unrecognized_format_is_none(self):
        self.assertIsNone(predicate_type_for_format("syft-native"))
        self.assertIsNone(predicate_type_for_format(""))

    def test_non_string_format_is_none(self):
        self.assertIsNone(predicate_type_for_format(None))
        self.assertIsNone(predicate_type_for_format(123))


class BuildSbomStatementTests(unittest.TestCase):
    def _raw_doc(self):
        return {"bomFormat": "CycloneDX", "specVersion": "1.5", "components": [{"name": "flask"}]}

    def test_cyclonedx_statement_shape(self):
        raw = self._raw_doc()
        statement = build_sbom_statement(
            subject_name="registry.example.com/org/svc",
            subject_sha256="a" * 64,
            sbom_format="cyclonedx",
            raw_document=raw,
        )
        self.assertEqual(statement["_type"], STATEMENT_TYPE)
        self.assertEqual(statement["subject"], [{"name": "registry.example.com/org/svc", "digest": {"sha256": "a" * 64}}])
        self.assertEqual(statement["predicateType"], CYCLONEDX_PREDICATE_TYPE)
        # Verbatim, not a re-derivation.
        self.assertEqual(statement["predicate"], raw)
        self.assertIs(statement["predicate"], raw)

    def test_spdx_statement_shape(self):
        raw = {"spdxVersion": "SPDX-2.3", "packages": []}
        statement = build_sbom_statement(
            subject_name="registry.example.com/org/svc", subject_sha256="b" * 64, sbom_format="spdx2", raw_document=raw
        )
        self.assertEqual(statement["predicateType"], SPDX_PREDICATE_TYPE)

    def test_subject_matches_the_same_shape_builder_py_uses(self):
        # Same {"name", "digest": {"sha256"}} shape cli.builder.
        # build_statement's own subject array uses, for the same artifact.
        statement = build_sbom_statement(
            subject_name="x", subject_sha256="c" * 64, sbom_format="cyclonedx", raw_document=self._raw_doc()
        )
        self.assertEqual(list(statement["subject"][0].keys()), ["name", "digest"])
        self.assertEqual(list(statement["subject"][0]["digest"].keys()), ["sha256"])

    def test_none_raw_document_returns_none(self):
        self.assertIsNone(
            build_sbom_statement(subject_name="x", subject_sha256="a" * 64, sbom_format="cyclonedx", raw_document=None)
        )

    def test_unrecognized_format_returns_none_even_with_a_real_document(self):
        self.assertIsNone(
            build_sbom_statement(
                subject_name="x", subject_sha256="a" * 64, sbom_format="syft-native", raw_document=self._raw_doc()
            )
        )

    def test_none_format_returns_none(self):
        self.assertIsNone(
            build_sbom_statement(subject_name="x", subject_sha256="a" * 64, sbom_format=None, raw_document=self._raw_doc())
        )


if __name__ == "__main__":
    unittest.main()
