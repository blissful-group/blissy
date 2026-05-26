import { expect, it } from "vitest";

import { compare } from "./compare";

it("returns true for equal strings", () => {
  expect(compare.string("state-123", "state-123")).toBe(true);
});

it("returns false for different strings with the same length", () => {
  expect(compare.string("state-123", "state-456")).toBe(false);
});

it("returns false for different strings with different lengths", () => {
  expect(compare.string("state", "state-123")).toBe(false);
});

it("returns true for empty strings", () => {
  expect(compare.string("", "")).toBe(true);
});

it("compares unicode strings", () => {
  expect(compare.string("state-ø", "state-ø")).toBe(true);
  expect(compare.string("state-ø", "state-å")).toBe(false);
});
