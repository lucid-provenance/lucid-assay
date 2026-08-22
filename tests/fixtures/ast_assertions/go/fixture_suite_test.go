// Fixture: Go testing/testify assertion patterns exercised by
// test_ast_assertions.py. Mirrors the categories exercised for every
// other language's fixture: standard/valid, gamed/tautological,
// zero-assertion, and skipped.
package fixtures

import (
	"testing"

	"github.com/stretchr/testify/assert"
)

func computeSomething() int {
	return 42
}

func TestValidStandardLibrary(t *testing.T) {
	result := 2 + 2
	if result != 4 {
		t.Errorf("expected 4, got %d", result)
	}
}

func TestValidTestify(t *testing.T) {
	value := computeSomething()
	assert.Equal(t, 42, value)
}

func TestGamedTrueLiteral(t *testing.T) {
	assert.True(t, true)
}

func TestGamedEqualLiteral(t *testing.T) {
	assert.Equal(t, 1, 1)
}

func TestZeroAssertions(t *testing.T) {
	value := computeSomething()
	_ = value
}

func TestSkippedWholesale(t *testing.T) {
	t.Skip("flaky in CI")
	assert.Equal(t, 1, 2)
}
