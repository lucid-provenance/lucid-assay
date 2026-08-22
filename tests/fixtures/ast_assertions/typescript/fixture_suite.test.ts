// Fixture: TypeScript/Jest assertion patterns exercised by
// test_ast_assertions.py. Mirrors the categories exercised for every
// other language's fixture: standard/valid, gamed/tautological,
// zero-assertion, and skipped.

function computeSomething(): number {
  return 42;
}

it("adds numbers correctly", () => {
  const result: number = 2 + 2;
  expect(result).toBe(4);
});

it("resolves an async value", async () => {
  const value: number = await Promise.resolve(computeSomething());
  expect(value).toEqual(42);
});

it("gamed literal true", () => {
  expect(true).toBe(true);
});

it("gamed self reference", () => {
  const x: number = computeSomething();
  expect(x).toBe(x);
});

test("zero assertions", () => {
  const value: number = computeSomething();
  console.log(value);
});

it.skip("skipped wholesale", () => {
  expect(1).toBe(2);
});
