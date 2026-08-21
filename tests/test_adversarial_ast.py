"""
Adversarial bypass suite for the AST assertion integrity engine.

Each of the 11 test functions below is a hand-crafted attempt to fool
`inspect_test_suite` into crediting a fake/unverifiable/statically-dead
"assertion" as a real one, grouped by the hardening item it targets:

  1. Scoped NodeVisitor (no `ast.walk`, no descending into nested defs/
     lambdas/classes; dead `if` branches and assertion-swallowing `try`
     blocks are pruned):
       test_delegated_helpers, test_inner_function_unreachable,
       test_unreachable, test_try_except_bypass

  2. Enhanced tautology / truthiness detection (recursive `not` unpacking,
     bare non-boolean literal/collection assertions, self-referential
     Eq/Is/In comparisons with constant folding):
       test_bool_taut, test_identity_taut, test_blind_truthiness

  3. Mock & assertion allowlisting (+ matcher idiom support):
       test_mock_assertions, test_matcher_library

  4. Empty context blocks (`with pytest.raises(...): pass` credits nothing):
       test_pytest_raises_empty

  test_custom_helpers is the baseline control: a hand-rolled global
  `assert_equals(a, b)` helper is not an attribute-based assert method, a
  mock method, or a matcher call, so it is correctly never credited.
"""
import os
import sys
import tempfile
import textwrap
import unittest

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from cli.parsers.ast_inspector import inspect_test_suite

ADVERSARIAL_SOURCE = """
import pytest

# 1. Boolean & Constant Tautologies
def test_bool_taut():
    assert not not True
    assert False or True
    assert 0 == 0
    assert "a" in "abc"

def test_identity_taut():
    x = [1, 2]
    assert x is x
    assert [] == []
    assert type(5) is int

# 2. Assert Without Comparison / Blind Truthiness
def test_blind_truthiness():
    x = 1
    assert x
    assert [1, 2, 3]
    assert "success"

# 3. Shadowed & Custom Assertion Helpers
def assert_equals(a, b):
    pass

def test_custom_helpers():
    assert_equals(1, 1)

def test_delegated_helpers():
    def check_something(x):
        assert x == 1
    check_something(1)

# 4. Mock & Spy Bypass
class MockObj:
    def assert_called_once(self): pass
    def assert_called_with(self, *args): pass
    def assert_called(self): pass

def test_mock_assertions():
    mock_obj = MockObj()
    mock_obj.assert_called_once()
    mock_obj.assert_called_with(1, 2)
    # Typo bypass!
    mock_obj.assert_called()

# 5. Control Flow & Unreachable Assertions
def test_unreachable():
    if False:
        assert 1 == 2

def test_inner_function_unreachable():
    def inner():
        assert False

def test_try_except_bypass():
    try:
        assert 1 == 2
    except AssertionError:
        pass

# 6. Non-Standard Pytest Invocations
def test_pytest_raises_empty():
    with pytest.raises(ValueError):
        pass

class Expectation:
    def __init__(self, val): self.val = val
    def to_equal(self, other): pass

def expect(val):
    return Expectation(val)

def test_matcher_library():
    expect(1).to_equal(1)
"""


class AdversarialASTBypassTests(unittest.TestCase):
    """Runs the inspector over the adversarial fixture once and checks both
    the aggregate totals and each function's individual breakdown, so a
    regression in any one bypass category fails on its own rather than
    hiding inside an aggregate count."""

    @classmethod
    def setUpClass(cls):
        cls._tmpdir = tempfile.TemporaryDirectory()
        path = os.path.join(cls._tmpdir.name, "test_adversarial_fixture.py")
        with open(path, "w", encoding="utf-8") as f:
            f.write(textwrap.dedent(ADVERSARIAL_SOURCE))
        cls.metrics = inspect_test_suite(cls._tmpdir.name, target_files=[path])
        cls.by_name = {
            fn.name: fn
            for file_result in cls.metrics.files
            for fn in file_result.test_functions
        }

    @classmethod
    def tearDownClass(cls):
        cls._tmpdir.cleanup()

    def _fn(self, name: str):
        self.assertIn(name, self.by_name, f"{name} was not discovered as a test function")
        return self.by_name[name]

    # -- fixture sanity --------------------------------------------------------

    def test_all_eleven_adversarial_functions_are_discovered(self):
        self.assertEqual(self.metrics.total_test_functions, 11)
        self.assertEqual(len(self.by_name), 11)

    # -- category 2: tautology / truthiness hardening --------------------------

    def test_bool_taut_all_four_asserts_are_tautological(self):
        fn = self._fn("test_bool_taut")
        # not-not unpacking, BoolOp constant folding, self-referential Eq,
        # and constant-folded In all catch a hardcoded-true assertion.
        self.assertEqual(fn.assertion_count, 0)
        self.assertEqual(fn.tautological_count, 4)

    def test_identity_taut_catches_provable_cases_only(self):
        fn = self._fn("test_identity_taut")
        # `x is x` and `[] == []` are self-referential/structural matches.
        # `type(5) is int` requires executing type() to prove, so it is
        # conservatively left as a real (uncredited-as-fake) assertion.
        self.assertEqual(fn.tautological_count, 2)
        self.assertEqual(fn.assertion_count, 1)

    def test_blind_truthiness_flags_bare_literals_not_names(self):
        fn = self._fn("test_blind_truthiness")
        # `assert [1, 2, 3]` and `assert "success"` are bare non-boolean
        # literal/collection tautologies; `assert x` depends on a name's
        # runtime value and is correctly left as a real check.
        self.assertEqual(fn.tautological_count, 2)
        self.assertEqual(fn.assertion_count, 1)

    # -- category 3: mock allowlisting + matcher idioms -------------------------

    def test_mock_assertions_allowlists_real_methods_and_ignores_typo(self):
        fn = self._fn("test_mock_assertions")
        # assert_called_once() and assert_called_with(...) are allowlisted;
        # the assert_called() typo is neither in the allowlist nor provably
        # a real check, so it is ignored rather than credited.
        self.assertEqual(fn.assertion_count, 2)
        self.assertEqual(fn.tautological_count, 0)

    def test_matcher_library_idiom_is_credited(self):
        fn = self._fn("test_matcher_library")
        self.assertEqual(fn.assertion_count, 1)
        self.assertEqual(fn.tautological_count, 0)

    def test_custom_helper_function_is_not_credited(self):
        fn = self._fn("test_custom_helpers")
        self.assertEqual(fn.assertion_count, 0)
        self.assertEqual(fn.tautological_count, 0)

    # -- category 1: scoped visitor / dead-code pruning --------------------------

    def test_delegated_nested_function_assertion_is_not_credited(self):
        fn = self._fn("test_delegated_helpers")
        self.assertEqual(fn.assertion_count, 0)
        self.assertEqual(fn.tautological_count, 0)

    def test_inner_function_assertion_is_not_credited(self):
        fn = self._fn("test_inner_function_unreachable")
        self.assertEqual(fn.assertion_count, 0)
        self.assertEqual(fn.tautological_count, 0)

    def test_dead_if_false_branch_is_pruned(self):
        fn = self._fn("test_unreachable")
        self.assertEqual(fn.assertion_count, 0)
        self.assertEqual(fn.tautological_count, 0)

    def test_try_except_assertion_error_swallow_is_suppressed(self):
        fn = self._fn("test_try_except_bypass")
        self.assertEqual(fn.assertion_count, 0)
        self.assertEqual(fn.tautological_count, 0)

    # -- category 4: empty context blocks ----------------------------------------

    def test_empty_pytest_raises_body_is_not_credited(self):
        fn = self._fn("test_pytest_raises_empty")
        self.assertEqual(fn.assertion_count, 0)
        self.assertEqual(fn.tautological_count, 0)

    # -- aggregate cross-check ----------------------------------------------------

    def test_aggregate_totals_match_the_per_function_breakdown(self):
        self.assertEqual(self.metrics.total_assertions, 5)
        self.assertEqual(self.metrics.tautological_assertions, 8)
        self.assertEqual(
            self.metrics.total_assertions,
            sum(fn.assertion_count for fn in self.by_name.values()),
        )
        self.assertEqual(
            self.metrics.tautological_assertions,
            sum(fn.tautological_count for fn in self.by_name.values()),
        )


if __name__ == "__main__":
    unittest.main()
