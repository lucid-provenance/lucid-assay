"""
Multi-language assertion integrity engine tests (`cli/parsers/ast/`).

Covers:
  1. FixtureSuiteTests: on-disk fixtures under tests/fixtures/ast_assertions/
     for every supported language (Python, TypeScript, JavaScript, Go,
     Java), each exercising standard/valid, gamed/tautological,
     zero-assertion, and skipped-test detection in one pass.
  2. Per-language inline-source tests for heuristics too specific to
     bundle into the shared fixture files (negated matcher chains, table-
     driven Go subtests, AssertJ chain double-count guarding, ...).
  3. Registry/dispatcher tests: correct visitor routing by naming
     convention, mixed multi-language repo-wide discovery, vendor/build
     directory skipping across every new language, and skipped-test
     exclusion from aggregate totals/density.
  4. DSSE predicate telemetry: `cli/builder.py`'s
     `assertion_density.languages` / `ast_skipped_test_functions` plumbing.
"""
import os
import sys
import tempfile
import textwrap
import unittest

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from cli.parsers.ast import inspect_test_suite
from cli.parsers.ast.go_visitor import GoAssertionVisitor
from cli.parsers.ast.java_visitor import JavaAssertionVisitor
from cli.parsers.ast.python_visitor import PythonAssertionVisitor
from cli.parsers.ast.tsjs_visitor import TsJsAssertionVisitor

FIXTURES_DIR = os.path.join(os.path.dirname(os.path.abspath(__file__)), "fixtures", "ast_assertions")


def _write(dirpath: str, filename: str, source: str) -> str:
    path = os.path.join(dirpath, filename)
    os.makedirs(os.path.dirname(path), exist_ok=True)
    with open(path, "w", encoding="utf-8") as f:
        f.write(textwrap.dedent(source))
    return path


def _by_name(result_files, name):
    for file_result in result_files:
        for fn in file_result.test_functions:
            if fn.name == name:
                return fn
    raise AssertionError(f"no test function named {name!r} found")


class FixtureSuiteTests(unittest.TestCase):
    """One fixture file per language, each covering valid/gamed/zero/skipped
    in a single pass -- see tests/fixtures/ast_assertions/<language>/."""

    def _inspect(self, subdir: str, filename: str):
        repo_dir = os.path.join(FIXTURES_DIR, subdir)
        return inspect_test_suite(repo_dir, target_files=[filename])

    def test_python_fixture_suite(self):
        metrics = self._inspect("python", "test_fixture_suite.py")
        self.assertEqual(metrics.files[0].parse_error, None)

        valid1 = _by_name(metrics.files, "test_valid_arithmetic")
        self.assertEqual((valid1.assertion_count, valid1.tautological_count), (1, 0))

        valid2 = _by_name(metrics.files, "test_valid_unittest_style")
        self.assertEqual((valid2.assertion_count, valid2.tautological_count), (2, 0))

        gamed1 = _by_name(metrics.files, "test_gamed_literal_true")
        self.assertEqual((gamed1.assertion_count, gamed1.tautological_count), (0, 1))

        gamed2 = _by_name(metrics.files, "test_gamed_self_reference")
        self.assertEqual((gamed2.assertion_count, gamed2.tautological_count), (0, 1))

        zero = _by_name(metrics.files, "test_zero_assertions")
        self.assertEqual(zero.assertion_count, 0)
        self.assertFalse(zero.is_empty_body)

        skipped = _by_name(metrics.files, "test_skipped_wholesale")
        self.assertTrue(skipped.is_skipped)

        # Skipped tests are recorded but excluded from suite-wide totals.
        self.assertEqual(metrics.skipped_test_functions, 1)
        self.assertEqual(metrics.total_test_functions, 5)
        self.assertEqual(metrics.total_assertions, 3)
        self.assertEqual(metrics.tautological_assertions, 2)

    def test_typescript_fixture_suite(self):
        metrics = self._inspect("typescript", "fixture_suite.test.ts")
        self.assertEqual(metrics.files[0].parse_error, None)
        # .ts is attributed to "typescript", not a merged bucket -- even
        # though one visitor implementation handles both.
        self.assertEqual(metrics.files[0].language, "typescript")

        valid1 = _by_name(metrics.files, "adds numbers correctly")
        self.assertEqual((valid1.assertion_count, valid1.tautological_count), (1, 0))

        valid2 = _by_name(metrics.files, "resolves an async value")
        self.assertEqual((valid2.assertion_count, valid2.tautological_count), (1, 0))

        gamed1 = _by_name(metrics.files, "gamed literal true")
        self.assertEqual((gamed1.assertion_count, gamed1.tautological_count), (0, 1))

        gamed2 = _by_name(metrics.files, "gamed self reference")
        self.assertEqual((gamed2.assertion_count, gamed2.tautological_count), (0, 1))

        zero = _by_name(metrics.files, "zero assertions")
        self.assertEqual(zero.assertion_count, 0)
        self.assertFalse(zero.is_empty_body)

        skipped = _by_name(metrics.files, "skipped wholesale")
        self.assertTrue(skipped.is_skipped)

        self.assertEqual(metrics.skipped_test_functions, 1)
        self.assertEqual(metrics.total_test_functions, 5)
        self.assertEqual(metrics.total_assertions, 2)
        self.assertEqual(metrics.tautological_assertions, 2)

    def test_javascript_fixture_suite(self):
        metrics = self._inspect("javascript", "fixture_suite.test.js")
        self.assertEqual(metrics.files[0].parse_error, None)
        self.assertEqual(metrics.files[0].language, "javascript")

        valid1 = _by_name(metrics.files, "adds numbers correctly")
        self.assertEqual((valid1.assertion_count, valid1.tautological_count), (1, 0))

        valid2 = _by_name(metrics.files, "uses bare node assert")
        self.assertEqual((valid2.assertion_count, valid2.tautological_count), (1, 0))

        gamed1 = _by_name(metrics.files, "gamed literal true")
        self.assertEqual((gamed1.assertion_count, gamed1.tautological_count), (0, 1))

        gamed2 = _by_name(metrics.files, "gamed chai equal")
        self.assertEqual((gamed2.assertion_count, gamed2.tautological_count), (0, 1))

        zero = _by_name(metrics.files, "zero assertions")
        self.assertEqual(zero.assertion_count, 0)

        skipped = _by_name(metrics.files, "skipped legacy alias")
        self.assertTrue(skipped.is_skipped)

        self.assertEqual(metrics.skipped_test_functions, 1)
        self.assertEqual(metrics.total_test_functions, 5)

    def test_go_fixture_suite(self):
        metrics = self._inspect("go", "fixture_suite_test.go")
        self.assertEqual(metrics.files[0].parse_error, None)

        valid1 = _by_name(metrics.files, "TestValidStandardLibrary")
        self.assertEqual((valid1.assertion_count, valid1.tautological_count), (1, 0))

        valid2 = _by_name(metrics.files, "TestValidTestify")
        self.assertEqual((valid2.assertion_count, valid2.tautological_count), (1, 0))

        gamed1 = _by_name(metrics.files, "TestGamedTrueLiteral")
        self.assertEqual((gamed1.assertion_count, gamed1.tautological_count), (0, 1))

        gamed2 = _by_name(metrics.files, "TestGamedEqualLiteral")
        self.assertEqual((gamed2.assertion_count, gamed2.tautological_count), (0, 1))

        zero = _by_name(metrics.files, "TestZeroAssertions")
        self.assertEqual(zero.assertion_count, 0)
        self.assertFalse(zero.is_empty_body)

        skipped = _by_name(metrics.files, "TestSkippedWholesale")
        self.assertTrue(skipped.is_skipped)

        self.assertEqual(metrics.skipped_test_functions, 1)
        self.assertEqual(metrics.total_test_functions, 5)
        self.assertEqual(metrics.total_assertions, 2)
        self.assertEqual(metrics.tautological_assertions, 2)

    def test_java_fixture_suite(self):
        metrics = self._inspect("java", "FixtureSuiteTest.java")
        self.assertEqual(metrics.files[0].parse_error, None)

        valid1 = _by_name(metrics.files, "validJUnitAssertion")
        self.assertEqual((valid1.assertion_count, valid1.tautological_count), (1, 0))

        valid2 = _by_name(metrics.files, "validAssertJChain")
        self.assertEqual((valid2.assertion_count, valid2.tautological_count), (1, 0))

        valid3 = _by_name(metrics.files, "validHamcrestBare")
        self.assertEqual((valid3.assertion_count, valid3.tautological_count), (1, 0))

        gamed1 = _by_name(metrics.files, "gamedBooleanLiteral")
        self.assertEqual((gamed1.assertion_count, gamed1.tautological_count), (0, 1))

        gamed2 = _by_name(metrics.files, "gamedAssertJLiteral")
        self.assertEqual((gamed2.assertion_count, gamed2.tautological_count), (0, 1))

        zero = _by_name(metrics.files, "zeroAssertions")
        self.assertEqual(zero.assertion_count, 0)

        skipped = _by_name(metrics.files, "skippedWholesale")
        self.assertTrue(skipped.is_skipped)

        self.assertEqual(metrics.skipped_test_functions, 1)
        self.assertEqual(metrics.total_test_functions, 6)
        self.assertEqual(metrics.total_assertions, 3)
        self.assertEqual(metrics.tautological_assertions, 2)


class TsJsInlineHeuristicTests(unittest.TestCase):

    def setUp(self):
        self._tmp = tempfile.TemporaryDirectory()
        self.repo_dir = self._tmp.name

    def tearDown(self):
        self._tmp.cleanup()

    def _inspect(self, filename: str, source: str):
        path = _write(self.repo_dir, filename, source)
        return inspect_test_suite(self.repo_dir, target_files=[path])

    def test_negated_matcher_is_never_tautological(self):
        metrics = self._inspect("negated.test.ts", """
            it("not equal check", () => {
              expect(true).not.toBe(true);
            });
        """)
        fn = _by_name(metrics.files, "not equal check")
        self.assertEqual((fn.assertion_count, fn.tautological_count), (1, 0))

    def test_resolves_rejects_passthrough_still_counts_terminal(self):
        metrics = self._inspect("async.test.ts", """
            it("resolves check", async () => {
              await expect(Promise.resolve(1)).resolves.toBe(1);
            });
        """)
        fn = _by_name(metrics.files, "resolves check")
        # The chain's origin (`Promise.resolve(1)`) isn't a literal, so this
        # isn't provably tautological even though the terminal arg is `1`
        # -- it's credited as a real assertion, and the `.resolves` link
        # itself must not be double-counted as a separate call.
        self.assertEqual(fn.assertion_count, 1)
        self.assertEqual(fn.tautological_count, 0)

    def test_foreach_callback_assertions_are_credited(self):
        metrics = self._inspect("foreach.test.ts", """
            it("checks every item", () => {
              [1, 2, 3].forEach((n) => {
                expect(n).toBeGreaterThan(0);
              });
            });
        """)
        fn = _by_name(metrics.files, "checks every item")
        self.assertEqual(fn.assertion_count, 1)

    def test_named_helper_function_not_credited(self):
        metrics = self._inspect("helper.test.ts", """
            it("defines but never calls a helper", () => {
              function helper() {
                expect(true).toBe(true);
              }
              const x = 1;
            });
        """)
        fn = _by_name(metrics.files, "defines but never calls a helper")
        self.assertEqual(fn.assertion_count, 0)
        self.assertEqual(fn.tautological_count, 0)
        self.assertFalse(fn.is_empty_body)

    def test_it_only_still_executes_and_counts(self):
        metrics = self._inspect("only.test.ts", """
            it.only("focused test", () => {
              expect(1).toBe(2);
            });
        """)
        fn = _by_name(metrics.files, "focused test")
        self.assertFalse(fn.is_skipped)
        self.assertEqual(fn.assertion_count, 1)

    def test_xtest_alias_is_skipped(self):
        metrics = self._inspect("xtest.test.ts", """
            xtest("legacy disabled", () => {
              expect(1).toBe(2);
            });
        """)
        fn = _by_name(metrics.files, "legacy disabled")
        self.assertTrue(fn.is_skipped)

    def test_it_todo_has_no_body_and_is_skipped(self):
        metrics = self._inspect("todo.test.ts", """
            it.todo("not implemented yet");
        """)
        fn = _by_name(metrics.files, "not implemented yet")
        self.assertTrue(fn.is_skipped)
        self.assertTrue(fn.is_empty_body)

    def test_empty_callback_body_flagged(self):
        metrics = self._inspect("empty.test.ts", """
            it("does nothing", () => {});
        """)
        fn = _by_name(metrics.files, "does nothing")
        self.assertTrue(fn.is_empty_body)
        self.assertEqual(fn.assertion_count, 0)

    def test_tsx_extension_parses_with_jsx(self):
        metrics = self._inspect("component.test.tsx", """
            it("renders a value", () => {
              const el = <div>{1}</div>;
              expect(el).toBeTruthy();
            });
        """)
        fn = _by_name(metrics.files, "renders a value")
        self.assertEqual(fn.assertion_count, 1)

    def test_dunder_tests_directory_is_discovered(self):
        path = _write(self.repo_dir, os.path.join("__tests__", "widget.js"), """
            it("plain file under __tests__", () => {
              expect(1).toBe(1 + 0);
            });
        """)
        metrics = inspect_test_suite(self.repo_dir)
        fn = _by_name(metrics.files, "plain file under __tests__")
        self.assertEqual(fn.assertion_count, 1)


class GoInlineHeuristicTests(unittest.TestCase):

    def setUp(self):
        self._tmp = tempfile.TemporaryDirectory()
        self.repo_dir = self._tmp.name

    def tearDown(self):
        self._tmp.cleanup()

    def _inspect(self, filename: str, source: str):
        path = _write(self.repo_dir, filename, source)
        return inspect_test_suite(self.repo_dir, target_files=[path])

    def test_subtest_assertions_are_credited(self):
        metrics = self._inspect("subtest_test.go", """
            package p

            import (
                "testing"
                "github.com/stretchr/testify/assert"
            )

            func TestTableDriven(t *testing.T) {
                cases := []int{1, 2, 3}
                for _, c := range cases {
                    t.Run("case", func(t *testing.T) {
                        assert.Equal(t, c, c)
                    })
                }
            }
        """)
        fn = _by_name(metrics.files, "TestTableDriven")
        # assert.Equal(t, c, c) is a self-referential tautology even though
        # it lives inside a t.Run subtest closure.
        self.assertEqual(fn.tautological_count, 1)

    def test_require_package_recognized(self):
        metrics = self._inspect("require_test.go", """
            package p

            import (
                "testing"
                "github.com/stretchr/testify/require"
            )

            func TestRequireStyle(t *testing.T) {
                v := compute()
                require.Equal(t, 4, v)
            }
        """)
        fn = _by_name(metrics.files, "TestRequireStyle")
        self.assertEqual((fn.assertion_count, fn.tautological_count), (1, 0))

    def test_non_test_helper_not_discovered(self):
        metrics = self._inspect("helper_test.go", """
            package p

            import "testing"

            func helperNotATest(x int) int {
                return x
            }

            func TestUsesHelper(t *testing.T) {
                if helperNotATest(2) != 2 {
                    t.Fail()
                }
            }
        """)
        names = {fn.name for f in metrics.files for fn in f.test_functions}
        self.assertEqual(names, {"TestUsesHelper"})

    def test_fail_now_recognized_as_assertion(self):
        metrics = self._inspect("failnow_test.go", """
            package p

            import "testing"

            func TestFailNow(t *testing.T) {
                ok := false
                if !ok {
                    t.FailNow()
                }
            }
        """)
        fn = _by_name(metrics.files, "TestFailNow")
        self.assertEqual(fn.assertion_count, 1)


class JavaInlineHeuristicTests(unittest.TestCase):

    def setUp(self):
        self._tmp = tempfile.TemporaryDirectory()
        self.repo_dir = self._tmp.name

    def tearDown(self):
        self._tmp.cleanup()

    def _inspect(self, filename: str, source: str):
        path = _write(self.repo_dir, filename, source)
        return inspect_test_suite(self.repo_dir, target_files=[path])

    def test_assertj_chain_not_double_counted(self):
        metrics = self._inspect("ChainTest.java", """
            import org.junit.jupiter.api.Test;
            import static org.assertj.core.api.Assertions.assertThat;

            public class ChainTest {
                @Test
                void checksChain() {
                    int x = compute();
                    assertThat(x).isEqualTo(4);
                }
            }
        """)
        fn = _by_name(metrics.files, "checksChain")
        self.assertEqual(fn.assertion_count, 1)
        self.assertEqual(fn.tautological_count, 0)

    def test_junit4_ignore_annotation_detected(self):
        metrics = self._inspect("LegacyTest.java", """
            import org.junit.Test;
            import org.junit.Ignore;
            import static org.junit.Assert.assertTrue;

            public class LegacyTest {
                @Ignore
                @Test
                public void oldSkippedTest() {
                    assertTrue(false);
                }
            }
        """)
        fn = _by_name(metrics.files, "oldSkippedTest")
        self.assertTrue(fn.is_skipped)

    def test_non_annotated_method_not_discovered(self):
        metrics = self._inspect("MixedTest.java", """
            import org.junit.jupiter.api.Test;
            import static org.junit.jupiter.api.Assertions.assertEquals;

            public class MixedTest {
                private int helper() { return 1; }

                @Test
                void realTest() {
                    assertEquals(1, helper());
                }
            }
        """)
        names = {fn.name for f in metrics.files for fn in f.test_functions}
        self.assertEqual(names, {"realTest"})

    def test_assert_throws_lambda_body_is_walked(self):
        metrics = self._inspect("ThrowsTest.java", """
            import org.junit.jupiter.api.Test;
            import static org.junit.jupiter.api.Assertions.*;

            public class ThrowsTest {
                @Test
                void throwsCase() {
                    assertThrows(IllegalArgumentException.class, () -> {
                        assertEquals(1, 1);
                        throw new IllegalArgumentException();
                    });
                }
            }
        """)
        fn = _by_name(metrics.files, "throwsCase")
        # assertThrows itself (1) + the tautological assertEquals nested in
        # the lambda (1) -- both are walked since the lambda body runs
        # synchronously as part of the assertThrows call.
        self.assertEqual(fn.assertion_count, 1)
        self.assertEqual(fn.tautological_count, 1)


class PythonInlineHeuristicTests(unittest.TestCase):

    def setUp(self):
        self._tmp = tempfile.TemporaryDirectory()
        self.repo_dir = self._tmp.name

    def tearDown(self):
        self._tmp.cleanup()

    def _inspect(self, filename: str, source: str):
        path = _write(self.repo_dir, filename, source)
        return inspect_test_suite(self.repo_dir, target_files=[path])

    def test_class_level_skip_decorator_propagates_to_methods(self):
        metrics = self._inspect("test_class_skip.py", """
            import unittest

            @unittest.skip("whole class disabled")
            class DisabledSuite(unittest.TestCase):
                def test_one(self):
                    self.assertEqual(1, 2)

                def test_two(self):
                    self.assertTrue(False)
        """)
        one = _by_name(metrics.files, "test_one")
        two = _by_name(metrics.files, "test_two")
        self.assertTrue(one.is_skipped)
        self.assertTrue(two.is_skipped)
        self.assertEqual(metrics.skipped_test_functions, 2)
        self.assertEqual(metrics.total_test_functions, 0)


class DeadBranchPruningTests(unittest.TestCase):
    """`if (statically-false) { assertion }` must not be credited as
    executed, mirroring python_visitor.py's dead-`if`-branch pruning, in
    every Tree-sitter-backed visitor."""

    def setUp(self):
        self._tmp = tempfile.TemporaryDirectory()
        self.repo_dir = self._tmp.name

    def tearDown(self):
        self._tmp.cleanup()

    def _inspect(self, filename: str, source: str):
        path = _write(self.repo_dir, filename, source)
        return inspect_test_suite(self.repo_dir, target_files=[path])

    def test_go_dead_if_branch_not_credited(self):
        metrics = self._inspect("dead_test.go", """
            package p
            import "testing"
            func TestDeadBranch(t *testing.T) {
                if false {
                    t.Error("never runs")
                } else {
                    t.Error("always runs")
                }
            }
        """)
        fn = _by_name(metrics.files, "TestDeadBranch")
        self.assertEqual(fn.assertion_count, 1)

    def test_go_helper_using_testing_tb_not_misclassified_as_test(self):
        metrics = self._inspect("tb_test.go", """
            package p
            import "testing"
            func TestHelper(tb testing.TB) int {
                return 1
            }
            func TestReal(t *testing.T) {
                if 1 != 1 {
                    t.Fail()
                }
            }
        """)
        names = {fn.name for f in metrics.files for fn in f.test_functions}
        self.assertEqual(names, {"TestReal"})

    def test_java_dead_if_branch_not_credited(self):
        metrics = self._inspect("DeadTest.java", """
            import org.junit.jupiter.api.Test;
            import static org.junit.jupiter.api.Assertions.assertTrue;

            public class DeadTest {
                @Test
                void deadBranch() {
                    if (false) {
                        assertTrue(false);
                    } else {
                        assertTrue(true);
                    }
                }
            }
        """)
        fn = _by_name(metrics.files, "deadBranch")
        self.assertEqual(fn.assertion_count, 0)
        self.assertEqual(fn.tautological_count, 1)

    def test_java_comment_only_body_is_empty(self):
        metrics = self._inspect("TodoTest.java", """
            import org.junit.jupiter.api.Test;

            public class TodoTest {
                @Test
                void notImplementedYet() {
                    // TODO
                }
            }
        """)
        fn = _by_name(metrics.files, "notImplementedYet")
        self.assertTrue(fn.is_empty_body)

    def test_tsjs_dead_if_branch_not_credited(self):
        metrics = self._inspect("dead.test.ts", """
            it("dead branch", () => {
              if (false) {
                expect(1).toBe(2);
              } else {
                expect(1).toBe(1 + 0);
              }
            });
        """)
        fn = _by_name(metrics.files, "dead branch")
        self.assertEqual(fn.assertion_count, 1)
        self.assertEqual(fn.tautological_count, 0)

    def test_tsjs_comment_only_body_is_empty(self):
        metrics = self._inspect("todo.test.ts", """
            it("not implemented yet", () => {
              // TODO
            });
        """)
        fn = _by_name(metrics.files, "not implemented yet")
        self.assertTrue(fn.is_empty_body)

    def test_tsjs_each_curried_call_not_misclassified(self):
        metrics = self._inspect("each.test.ts", """
            it.each([[1, 2]])("adds %i and %i", (a, b) => {
              expect(a + b).toBe(3);
            });
        """)
        # Unsupported (curried) rather than misreported: no spurious
        # "<anonymous>" zero-assertion entry should appear.
        names = {fn.name for f in metrics.files for fn in f.test_functions}
        self.assertNotIn("<anonymous>", names)


class RegistryDispatchTests(unittest.TestCase):
    """Cross-language repo-wide discovery and aggregation."""

    def setUp(self):
        self._tmp = tempfile.TemporaryDirectory()
        self.repo_dir = self._tmp.name

    def tearDown(self):
        self._tmp.cleanup()

    def test_visitor_matches_are_mutually_exclusive_by_convention(self):
        self.assertTrue(PythonAssertionVisitor().matches("tests/test_foo.py"))
        self.assertFalse(PythonAssertionVisitor().matches("tests/foo.go"))
        self.assertTrue(GoAssertionVisitor().matches("pkg/foo_test.go"))
        self.assertFalse(GoAssertionVisitor().matches("pkg/foo.go"))
        self.assertTrue(JavaAssertionVisitor().matches("src/FooTest.java"))
        self.assertTrue(JavaAssertionVisitor().matches("src/FooTests.java"))
        self.assertTrue(JavaAssertionVisitor().matches("src/FooTestCase.java"))
        self.assertFalse(JavaAssertionVisitor().matches("src/Foo.java"))
        self.assertTrue(TsJsAssertionVisitor().matches("src/foo.test.ts"))
        self.assertTrue(TsJsAssertionVisitor().matches("src/foo.spec.js"))
        self.assertFalse(TsJsAssertionVisitor().matches("src/foo.ts"))

    def test_mixed_language_repo_discovery_and_aggregation(self):
        _write(self.repo_dir, "tests/test_py_sample.py", """
            def test_one():
                assert 1 == 1 - 0
        """)
        _write(self.repo_dir, "web/sample.test.js", """
            it("one", () => { expect(1).toBe(1 - 0); });
        """)
        _write(self.repo_dir, "svc/sample_test.go", """
            package p
            import "testing"
            func TestOne(t *testing.T) {
                if 1 != 1 {
                    t.Fail()
                }
            }
        """)
        _write(self.repo_dir, "app/SampleTest.java", """
            import org.junit.jupiter.api.Test;
            import static org.junit.jupiter.api.Assertions.assertTrue;
            public class SampleTest {
                @Test
                void one() { assertTrue(1 == 1); }
            }
        """)
        # Vendor/build trees across every language must still be skipped.
        _write(self.repo_dir, "web/node_modules/pkg/pkg.test.js", """
            it("vendored", () => { expect(1).toBe(1); });
        """)
        _write(self.repo_dir, "svc/vendor/dep/dep_test.go", """
            package dep
            import "testing"
            func TestVendored(t *testing.T) {}
        """)

        metrics = inspect_test_suite(self.repo_dir)

        self.assertEqual(metrics.files_scanned, 4)
        self.assertEqual(metrics.total_test_functions, 4)
        self.assertEqual(
            set(metrics.languages.keys()),
            {"python", "javascript", "go", "java"},
        )
        for lang_metrics in metrics.languages.values():
            self.assertEqual(lang_metrics.files_scanned, 1)
            self.assertEqual(lang_metrics.total_test_functions, 1)

    def test_skipped_tests_excluded_from_density_but_counted_separately(self):
        _write(self.repo_dir, "a_test.go", """
            package p
            import "testing"
            func TestSkippedOne(t *testing.T) {
                t.Skip()
            }
            func TestRealOne(t *testing.T) {
                if 1 != 1 {
                    t.Fail()
                }
            }
        """)
        metrics = inspect_test_suite(self.repo_dir)
        self.assertEqual(metrics.skipped_test_functions, 1)
        self.assertEqual(metrics.total_test_functions, 1)
        self.assertEqual(metrics.assertion_density, 1.0)

    def test_target_files_scans_non_conventionally_named_path_by_extension(self):
        # A diff-touched helper module that doesn't follow the test_*.py
        # naming convention -- target_files mode must still resolve it by
        # extension rather than silently dropping it (the single-language
        # engine this replaced never filtered target_files by name at all).
        path = _write(self.repo_dir, "conftest.py", """
            def test_helper_defined_here():
                result = 2 - 1
                assert result == 1
        """)
        metrics = inspect_test_suite(self.repo_dir, target_files=[path])
        self.assertEqual(metrics.files_scanned, 1)
        fn = _by_name(metrics.files, "test_helper_defined_here")
        self.assertEqual(fn.assertion_count, 1)

    def test_target_files_still_ignores_unrecognized_extensions(self):
        path = _write(self.repo_dir, "notes.txt", "just some text")
        metrics = inspect_test_suite(self.repo_dir, target_files=[path])
        self.assertEqual(metrics.files_scanned, 0)


class TelemetryIntegrationTests(unittest.TestCase):
    """DSSE predicate wiring: cli/builder.py's assertion_density.languages
    and heuristics.ast_skipped_test_functions fields."""

    def test_predicate_embeds_per_language_breakdown_and_skip_count(self):
        from tests.test_builder import _base_kwargs
        from cli.builder import build_statement

        languages = {
            "python": {
                "files_scanned": 3,
                "total_test_functions": 20,
                "total_assertions": 40,
                "tautological_assertions": 1,
                "empty_test_bodies": 0,
                "skipped_test_functions": 2,
            },
            "go": {
                "files_scanned": 1,
                "total_test_functions": 5,
                "total_assertions": 5,
                "tautological_assertions": 0,
                "empty_test_bodies": 0,
                "skipped_test_functions": 0,
            },
        }
        statement = build_statement(
            **_base_kwargs(ast_languages=languages, ast_skipped_test_functions=2)
        )
        predicate = statement["predicate"]
        self.assertEqual(predicate["assertion_density"]["languages"], languages)
        self.assertEqual(
            predicate["assertion_density"]["heuristics"]["ast_skipped_test_functions"], 2
        )

    def test_predicate_defaults_to_empty_languages_when_omitted(self):
        from tests.test_builder import _base_kwargs
        from cli.builder import build_statement

        statement = build_statement(**_base_kwargs())
        predicate = statement["predicate"]
        self.assertEqual(predicate["assertion_density"]["languages"], {})
        self.assertEqual(predicate["assertion_density"]["heuristics"]["ast_skipped_test_functions"], 0)


class BackwardCompatShimTests(unittest.TestCase):
    """cli/parsers/ast_inspector.py must keep re-exporting the same names
    after the move to cli/parsers/ast/."""

    def test_shim_reexports_inspect_test_suite(self):
        from cli.parsers.ast_inspector import inspect_test_suite as shimmed
        from cli.parsers.ast import inspect_test_suite as canonical

        self.assertIs(shimmed, canonical)


if __name__ == "__main__":
    unittest.main()
