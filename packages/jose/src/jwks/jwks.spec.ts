import { Effect } from "effect";
import { expect, it } from "vitest";

import { JWKS } from "./jwks";

const set = {
  keys: [
    {
      kty: "oct",
      kid: "sig-1",
      alg: "HS256",
      use: "sig",
      k: "c3VwZXItc2VjcmV0LXNpZ25pbmcta2V5",
    },
    {
      kty: "RSA",
      kid: "enc-1",
      alg: "RSA-OAEP",
      use: "enc",
      n: "modulus",
      e: "AQAB",
    },
    {
      kty: "EC",
      kid: "sig-2",
      alg: "ES256",
      use: "sig",
      crv: "P-256",
      x: "x-coordinate",
      y: "y-coordinate",
    },
  ],
};

it("parses a JWK Set", async () => {
  const parsed = await Effect.runPromise(JWKS.parse(set));

  expect(parsed).toEqual(set);
});

it("rejects a JWK Set without a keys array", async () => {
  const effect = Effect.match(JWKS.parse({}), {
    onFailure: (error) => error,
    onSuccess: () => null,
  });

  const error = await Effect.runPromise(effect);

  expect(error).toBeInstanceOf(JWKS.ParseError);
  expect(error?._tag).toBe("JWKSParseError");
  expect(error?.message).toBe("Invalid JWKS: missing keys array");
});

it("finds a key by kid", async () => {
  const key = await Effect.runPromise(
    JWKS.findKey({
      set,
      kid: "enc-1",
    }),
  );

  expect(key).toEqual(set.keys[1]);
});

it("filters keys by alg", async () => {
  const key = await Effect.runPromise(
    JWKS.findKey({
      set,
      alg: "ES256",
    }),
  );

  expect(key).toEqual(set.keys[2]);
});

it("filters keys by kty", async () => {
  const key = await Effect.runPromise(
    JWKS.findKey({
      set,
      kty: "RSA",
    }),
  );

  expect(key).toEqual(set.keys[1]);
});

it("filters keys by use", async () => {
  const key = await Effect.runPromise(
    JWKS.findKey({
      set,
      use: "enc",
    }),
  );

  expect(key).toEqual(set.keys[1]);
});

it("rejects ambiguous key matches", async () => {
  const effect = Effect.match(
    JWKS.findKey({
      set,
      use: "sig",
    }),
    {
      onFailure: (error) => error,
      onSuccess: () => null,
    },
  );

  const error = await Effect.runPromise(effect);

  expect(error).toBeInstanceOf(JWKS.KeyMatchError);
  expect(error?._tag).toBe("JWKSKeyMatchError");
  expect(error?.message).toBe("Multiple JWKS keys matched the given criteria");
});
