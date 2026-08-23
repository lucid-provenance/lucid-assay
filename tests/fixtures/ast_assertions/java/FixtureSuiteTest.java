// Fixture: JUnit 5 + AssertJ + Hamcrest assertion patterns exercised by
// test_ast_assertions.py. Mirrors the categories exercised for every
// other language's fixture: standard/valid, gamed/tautological,
// zero-assertion, and skipped.
//
// This file is never compiled or classpath-resolved -- cli/parsers/ast/
// java_visitor.py parses it with Tree-sitter's grammar only, which has no
// notion of packages/directories at all, so the fixture intentionally
// lives at a fixed path (tests/fixtures/ast_assertions/java/
// FixtureSuiteTest.java, referenced by hardcoded name in
// tests/test_ast_assertions.py) rather than under a matching
// com/example/fixtures/ directory tree.
package com.example.fixtures; // NOSONAR: static parser fixture, not compiled -- see note above

import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.Disabled;
import static org.junit.jupiter.api.Assertions.*;
import static org.assertj.core.api.Assertions.assertThat;
import static org.hamcrest.Matchers.equalTo;

public class FixtureSuiteTest {

    private int computeSomething() {
        return 42;
    }

    @Test
    void validJUnitAssertion() {
        int result = 2 + 2;
        assertEquals(4, result);
    }

    @Test
    void validAssertJChain() {
        int value = computeSomething();
        assertThat(value).isEqualTo(42);
    }

    @Test
    void validHamcrestBare() {
        assertThat(computeSomething(), equalTo(42));
    }

    @Test
    void gamedBooleanLiteral() {
        assertTrue(true);
    }

    @Test
    void gamedAssertJLiteral() {
        assertThat(true).isTrue();
    }

    @Test
    void zeroAssertions() {
        int value = computeSomething();
        System.out.println(value);
    }

    @Test
    @Disabled("flaky in CI")
    void skippedWholesale() {
        assertEquals(1, 2);
    }
}
