import { expect, it } from "vitest";

import { Filters } from "./filters";

const keys = [
  {
    alg: "HS256",
    kid: "sig-1",
    kty: "oct",
    use: "sig",
  },
  {
    alg: "RSA-OAEP",
    kid: "enc-1",
    kty: "RSA",
    use: "enc",
  },
  {
    alg: "ES256",
    kid: "sig-2",
    kty: "EC",
    use: "sig",
  },
];

it("matches all keys without criteria", () => {
  expect(keys.filter(Filters.keys({}))).toEqual(keys);
});

it("filters keys by kid", () => {
  expect(keys.filter(Filters.keys({ kid: "enc-1" }))).toEqual([keys[1]]);
});

it("filters keys by alg", () => {
  expect(keys.filter(Filters.keys({ alg: "ES256" }))).toEqual([keys[2]]);
});

it("filters keys by kty", () => {
  expect(keys.filter(Filters.keys({ kty: "RSA" }))).toEqual([keys[1]]);
});

it("filters keys by use", () => {
  expect(keys.filter(Filters.keys({ use: "sig" }))).toEqual([keys[0], keys[2]]);
});

it("requires all provided criteria to match", () => {
  expect(keys.filter(Filters.keys({ alg: "HS256", kid: "sig-1" }))).toEqual([
    keys[0],
  ]);
  expect(keys.filter(Filters.keys({ alg: "HS256", kid: "enc-1" }))).toEqual([]);
});
