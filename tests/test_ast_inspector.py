import os
import sys
import tempfile
import textwrap
import unittest

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from cli.parsers.ast_inspector import inspect_test_suite


def _write_test_file(dirpath: str, filename: str, source: str) -> str:
    path = os.path.join(dirpath, filename)
    with open(path, "w", encoding="utf-8") as f:
        f.write(textwrap.dedent(source))
    return path


class ASTInspectorTests(unittest.TestCase):

    def setUp(self):
        self._tmpdir = tempfile.TemporaryDirectory()
        self.repo_dir = self._tmpdir.name

    def tearDown(self):
        self._tmpdir.cleanup()

    def _inspect(self, filename: str, source: str):
        path = _write_test_file(self.repo_dir, filename, source)
        return inspect_test_suite(self.repo_dir, target_files=[path])

    # -- real assertions -------------------------------------------------

    def test_plain_assert_expression_is_counted(self):
        metrics = self._inspect("test_plain.py", """
            def test_addition():
                result = 1 + 1
                assert result == 2
        """)
        self.assertEqual(metrics.total_test_functions, 1)
        self.assertEqual(metrics.total_assertions, 1)
        self.assertEqual(metrics.tautological_assertions, 0)
        self.assertEqual(metrics.empty_test_bodies, 0)

    def test_self_assert_star_methods_are_counted(self):
        metrics = self._inspect("test_unittest_style.py", """
            import unittest

            class MyTests(unittest.TestCase):
                def test_things(self):
                    self.assertEqual(2 + 2, 4)
                    self.assertIn("a", "abc")
                    self.assertRaises(ValueError, int, "not-a-number")
        """)
        self.assertEqual(metrics.total_test_functions, 1)
        self.assertEqual(metrics.total_assertions, 3)
        self.assertEqual(metrics.tautological_assertions, 0)

    def test_pytest_raises_and_warns_are_counted(self):
        metrics = self._inspect("test_pytest_style.py", """
            import pytest
            import warnings

            def test_raises_value_error():
                with pytest.raises(ValueError):
                    int("nope")

            def test_warns_deprecation():
                with pytest.warns(DeprecationWarning):
                    warnings.warn("old", DeprecationWarning)
        """)
        self.assertEqual(metrics.total_test_functions, 2)
        self.assertEqual(metrics.total_assertions, 2)
        self.assertEqual(metrics.tautological_assertions, 0)

    def test_self_assert_raises_context_manager_is_counted(self):
        # Regression guard: unittest's own `with self.assertRaises(...):`
        # idiom used to be completely invisible to this engine -- neither
        # counted as an assertion nor even generically visited -- because
        # _handle_with only special-cased pytest.raises/pytest.warns.
        metrics = self._inspect("test_unittest_raises.py", """
            import unittest

            class MyTests(unittest.TestCase):
                def test_raises(self):
                    with self.assertRaises(ValueError):
                        int("nope")
        """)
        self.assertEqual(metrics.total_test_functions, 1)
        self.assertEqual(metrics.total_assertions, 1)
        self.assertEqual(metrics.valid_test_functions, 1)

    def test_self_assert_warns_context_manager_is_counted(self):
        metrics = self._inspect("test_unittest_warns.py", """
            import unittest
            import warnings

            class MyTests(unittest.TestCase):
                def test_warns(self):
                    with self.assertWarns(DeprecationWarning):
                        warnings.warn("old", DeprecationWarning)
        """)
        self.assertEqual(metrics.total_test_functions, 1)
        self.assertEqual(metrics.total_assertions, 1)

    def test_assert_raises_regex_context_manager_is_counted(self):
        metrics = self._inspect("test_unittest_raises_regex.py", """
            import unittest

            class MyTests(unittest.TestCase):
                def test_raises_regex(self):
                    with self.assertRaisesRegex(ValueError, "nope"):
                        int("nope")
        """)
        self.assertEqual(metrics.total_assertions, 1)

    def test_assert_raises_context_manager_as_clause_is_counted(self):
        # `as cm:` binding the exception context must not change detection.
        metrics = self._inspect("test_unittest_raises_as.py", """
            import unittest

            class MyTests(unittest.TestCase):
                def test_raises_as(self):
                    with self.assertRaises(ValueError) as cm:
                        int("nope")
                    self.assertIn("invalid literal", str(cm.exception))
        """)
        # The context manager itself, plus the follow-up assertIn.
        self.assertEqual(metrics.total_assertions, 2)

    def test_empty_body_under_self_assert_raises_is_not_counted(self):
        # Mirrors the existing empty `with pytest.raises(...): pass` case:
        # nothing in the block can actually raise, so it's still vanity.
        metrics = self._inspect("test_unittest_raises_empty.py", """
            import unittest

            class MyTests(unittest.TestCase):
                def test_raises_empty(self):
                    with self.assertRaises(ValueError):
                        pass
        """)
        self.assertEqual(metrics.total_assertions, 0)
        self.assertEqual(metrics.valid_test_functions, 0)

    def test_assert_raises_direct_call_form_still_counted(self):
        # The older, non-context-manager form (self.assertRaises(Exc, fn,
        # *args)) was already handled by visit_Call's generic assert*
        # dispatch -- confirms the new _handle_with path didn't regress it.
        metrics = self._inspect("test_unittest_raises_direct.py", """
            import unittest

            class MyTests(unittest.TestCase):
                def test_raises_direct(self):
                    self.assertRaises(ValueError, int, "nope")
        """)
        self.assertEqual(metrics.total_assertions, 1)

    def test_suffix_named_test_function_is_discovered(self):
        metrics = self._inspect("checks_test.py", """
            def addition_test():
                assert 2 + 2 == 4
        """)
        self.assertEqual(metrics.total_test_functions, 1)
        self.assertEqual(metrics.total_assertions, 1)

    def test_non_test_functions_are_ignored(self):
        metrics = self._inspect("test_helpers.py", """
            def helper():
                assert True  # not a test function, shouldn't be scanned

            def test_real_one():
                assert 1 == 1  # tautological, but this *is* a test function
        """)
        self.assertEqual(metrics.total_test_functions, 1)
        self.assertEqual(metrics.tautological_assertions, 1)

    # -- tautological / bogus assertions ----------------------------------

    def test_assert_true_literal_is_tautological(self):
        metrics = self._inspect("test_bogus_true.py", """
            def test_nothing():
                assert True
        """)
        self.assertEqual(metrics.total_assertions, 0)
        self.assertEqual(metrics.tautological_assertions, 1)

    def test_assert_one_equals_one_is_tautological(self):
        metrics = self._inspect("test_bogus_eq.py", """
            def test_nothing():
                assert 1 == 1
        """)
        self.assertEqual(metrics.total_assertions, 0)
        self.assertEqual(metrics.tautological_assertions, 1)

    def test_assert_not_false_is_tautological(self):
        metrics = self._inspect("test_bogus_not_false.py", """
            def test_nothing():
                assert not False
        """)
        self.assertEqual(metrics.total_assertions, 0)
        self.assertEqual(metrics.tautological_assertions, 1)

    def test_self_assert_true_literal_is_tautological(self):
        metrics = self._inspect("test_bogus_unittest.py", """
            import unittest

            class MyTests(unittest.TestCase):
                def test_nothing(self):
                    self.assertTrue(True)
        """)
        self.assertEqual(metrics.total_assertions, 0)
        self.assertEqual(metrics.tautological_assertions, 1)

    def test_self_comparison_is_tautological(self):
        metrics = self._inspect("test_self_compare.py", """
            def test_nothing():
                x = compute()
                assert x == x
        """)
        self.assertEqual(metrics.total_assertions, 0)
        self.assertEqual(metrics.tautological_assertions, 1)

    def test_mixed_real_and_tautological_assertions_are_both_tallied(self):
        metrics = self._inspect("test_mixed.py", """
            def test_partial_bogus():
                result = do_work()
                assert result is not None
                assert True
        """)
        self.assertEqual(metrics.total_assertions, 1)
        self.assertEqual(metrics.tautological_assertions, 1)

    # -- valid (non-vanity) test functions -----------------------------------

    def test_function_with_real_assertion_is_valid(self):
        metrics = self._inspect("test_valid.py", """
            def test_real():
                assert 1 + 1 == 2
        """)
        self.assertEqual(metrics.valid_test_functions, 1)
        self.assertEqual(metrics.valid_test_ratio, 1.0)

    def test_function_with_only_tautological_assertion_is_not_valid(self):
        metrics = self._inspect("test_vanity_taut.py", """
            def test_bogus():
                assert True
        """)
        self.assertEqual(metrics.valid_test_functions, 0)
        self.assertEqual(metrics.valid_test_ratio, 0.0)

    def test_empty_body_function_is_not_valid(self):
        metrics = self._inspect("test_vanity_empty.py", """
            def test_todo():
                pass
        """)
        self.assertEqual(metrics.valid_test_functions, 0)

    def test_function_with_one_real_and_one_tautological_assertion_is_valid(self):
        # Regression guard: assertion_count/tautological_count are disjoint
        # per-assertion counters (see cli.parsers.ast._tally's own
        # comment), so a function isn't penalized to "not valid" just for
        # also containing a tautological assertion alongside a real one.
        metrics = self._inspect("test_mixed_valid.py", """
            def test_partial_bogus():
                result = do_work()
                assert result is not None
                assert True
        """)
        self.assertEqual(metrics.valid_test_functions, 1)

    def test_valid_test_ratio_across_mixed_suite(self):
        metrics = self._inspect("test_ratio.py", """
            def test_one():
                assert 1 + 1 == 2

            def test_two():
                assert True

            def test_three():
                pass
        """)
        self.assertEqual(metrics.total_test_functions, 3)
        self.assertEqual(metrics.valid_test_functions, 1)
        self.assertAlmostEqual(metrics.valid_test_ratio, 1 / 3)

    def test_skipped_test_function_excluded_from_valid_test_ratio(self):
        metrics = self._inspect("test_skip.py", """
            import unittest

            class MyTests(unittest.TestCase):
                @unittest.skip("flaky")
                def test_disabled(self):
                    assert 1 == 1
        """)
        self.assertEqual(metrics.total_test_functions, 0)
        self.assertEqual(metrics.valid_test_functions, 0)
        self.assertEqual(metrics.valid_test_ratio, 0.0)

    # -- empty test bodies --------------------------------------------------

    def test_pass_only_body_is_empty(self):
        metrics = self._inspect("test_empty_pass.py", """
            def test_todo():
                pass
        """)
        self.assertEqual(metrics.empty_test_bodies, 1)
        self.assertEqual(metrics.total_assertions, 0)

    def test_ellipsis_only_body_is_empty(self):
        metrics = self._inspect("test_empty_ellipsis.py", """
            def test_todo():
                ...
        """)
        self.assertEqual(metrics.empty_test_bodies, 1)

    def test_docstring_only_body_is_empty(self):
        metrics = self._inspect("test_empty_docstring.py", """
            def test_todo():
                \"\"\"TODO: implement this test.\"\"\"
        """)
        self.assertEqual(metrics.empty_test_bodies, 1)

    def test_docstring_plus_pass_body_is_empty(self):
        metrics = self._inspect("test_empty_docstring_pass.py", """
            def test_todo():
                \"\"\"TODO: implement this test.\"\"\"
                pass
        """)
        self.assertEqual(metrics.empty_test_bodies, 1)

    def test_body_with_real_assertion_is_not_empty(self):
        metrics = self._inspect("test_not_empty.py", """
            def test_real():
                \"\"\"Docstring plus a real check.\"\"\"
                assert 1 + 1 == 2
        """)
        self.assertEqual(metrics.empty_test_bodies, 0)
        self.assertEqual(metrics.total_assertions, 1)

    # -- aggregation across files / functions --------------------------------

    def test_aggregates_across_multiple_functions_in_one_file(self):
        metrics = self._inspect("test_multi.py", """
            def test_one():
                assert 1 == 2 - 1

            def test_two():
                assert True

            def test_three():
                pass
        """)
        self.assertEqual(metrics.total_test_functions, 3)
        self.assertEqual(metrics.total_assertions, 1)
        self.assertEqual(metrics.tautological_assertions, 1)
        self.assertEqual(metrics.empty_test_bodies, 1)

    def test_aggregates_across_multiple_files(self):
        path_a = _write_test_file(self.repo_dir, "test_a.py", """
            def test_a():
                assert 1 == 1
        """)
        path_b = _write_test_file(self.repo_dir, "test_b.py", """
            def test_b():
                assert 2 == 2 - 0
                assert 3 > 2
        """)
        metrics = inspect_test_suite(self.repo_dir, target_files=[path_a, path_b])
        self.assertEqual(metrics.files_scanned, 2)
        self.assertEqual(metrics.total_test_functions, 2)
        # test_a is fully tautological (assert 1 == 1); test_b has two real checks.
        self.assertEqual(metrics.tautological_assertions, 1)
        self.assertEqual(metrics.total_assertions, 2)

    def test_repo_wide_discovery_without_target_files(self):
        _write_test_file(self.repo_dir, "test_discovered.py", """
            def test_discovered():
                assert 1 == 1 + 0
        """)
        nested_dir = os.path.join(self.repo_dir, "nested")
        os.makedirs(nested_dir, exist_ok=True)
        _write_test_file(nested_dir, "widget_test.py", """
            def widget_test():
                assert compute_widget() == "ok"
        """)
        # a non-test file with the same kind of content should not be scanned
        _write_test_file(self.repo_dir, "helpers.py", """
            def test_should_not_be_found():
                assert False
        """)

        metrics = inspect_test_suite(self.repo_dir)
        self.assertEqual(metrics.files_scanned, 2)
        self.assertEqual(metrics.total_test_functions, 2)

    def test_skips_vendor_style_directories_during_discovery(self):
        vendored = os.path.join(self.repo_dir, "node_modules", "some_pkg")
        os.makedirs(vendored, exist_ok=True)
        _write_test_file(vendored, "test_vendored.py", """
            def test_should_not_be_found():
                assert True
        """)
        metrics = inspect_test_suite(self.repo_dir)
        self.assertEqual(metrics.files_scanned, 0)
        self.assertEqual(metrics.total_test_functions, 0)

    # -- error handling -------------------------------------------------------

    def test_syntax_error_is_captured_not_raised(self):
        metrics = self._inspect("test_broken.py", """
            def test_broken(:
                assert True
        """)
        self.assertEqual(metrics.files_scanned, 1)
        self.assertEqual(len(metrics.parse_errors), 1)
        self.assertEqual(metrics.total_test_functions, 0)

    def test_missing_file_is_captured_not_raised(self):
        missing_path = os.path.join(self.repo_dir, "test_does_not_exist.py")
        metrics = inspect_test_suite(self.repo_dir, target_files=[missing_path])
        self.assertEqual(metrics.files_scanned, 1)
        self.assertEqual(len(metrics.parse_errors), 1)
        self.assertEqual(metrics.total_test_functions, 0)

    # -- __test__ opt-out on metrics dataclasses ------------------------------

    def test_metrics_dataclasses_are_marked_non_collectible(self):
        from cli.parsers.ast_inspector import (
            FileInspectionResult,
            TestFunctionMetrics,
            TestSuiteMetrics,
        )

        self.assertFalse(TestFunctionMetrics.__test__)
        self.assertFalse(FileInspectionResult.__test__)
        self.assertFalse(TestSuiteMetrics.__test__)


if __name__ == "__main__":
    unittest.main()
