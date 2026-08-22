// Fixture: JavaScript/Mocha (chai `assert`) patterns exercised by
// test_ast_assertions.py. Mirrors the categories exercised for every
// other language's fixture: standard/valid, gamed/tautological,
// zero-assertion, and skipped.
const assert = require("chai").assert;

function computeSomething() {
  return 42;
}

it("adds numbers correctly", () => {
  const result = 2 + 2;
  assert.equal(result, 4);
});

it("uses bare node assert", () => {
  const value = computeSomething();
  assert(value === 42);
});

it("gamed literal true", () => {
  assert(true);
});

it("gamed chai equal", () => {
  assert.equal(1, 1);
});

test("zero assertions", () => {
  const value = computeSomething();
  console.log(value);
});

xit("skipped legacy alias", () => {
  assert.equal(1, 2);
});
