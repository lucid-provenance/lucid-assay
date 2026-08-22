"""Fixture: Python assertion patterns exercised by test_ast_assertions.py.
Mirrors the categories exercised for every other language's fixture:
standard/valid, gamed/tautological, zero-assertion, and skipped."""
import unittest


def test_valid_arithmetic():
    result = 2 + 2
    assert result == 4


def test_valid_unittest_style():
    case = unittest.TestCase()
    case.assertEqual(3 * 3, 9)
    case.assertIn("a", "abc")


def test_gamed_literal_true():
    assert True


def test_gamed_self_reference():
    x = compute_something()
    assert x == x


def test_zero_assertions():
    value = compute_something()
    log(value)


@unittest.skip("flaky in CI")
def test_skipped_wholesale():
    assert 1 == 2
