import { Effect } from "effect";
import { expect, it } from "vitest";

import { JWK } from "./jwk";

const jwkSet = {
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
  const parsed = await Effect.runPromise(JWK.parseSet(jwkSet));

  expect(parsed).toEqual(jwkSet);
});

it("rejects a JWK Set without a keys array", async () => {
  const effect = Effect.match(JWK.parseSet({}), {
    onFailure: (error) => error,
    onSuccess: () => null,
  });

  const error = await Effect.runPromise(effect);

  expect(error).toBeInstanceOf(JWK.SetParseError);
  expect(error?._tag).toBe("JWKSetParseError");
  expect(error?.message).toBe("Invalid JWK Set: missing keys array");
});

it("finds a key by kid", async () => {
  const key = await Effect.runPromise(
    JWK.findKey({
      set: jwkSet,
      kid: "enc-1",
    }),
  );

  expect(key).toEqual(jwkSet.keys[1]);
});

it("rejects ambiguous key matches", async () => {
  const effect = Effect.match(
    JWK.findKey({
      set: jwkSet,
      use: "sig",
    }),
    {
      onFailure: (error) => error,
      onSuccess: () => null,
    },
  );

  const error = await Effect.runPromise(effect);

  expect(error).toBeInstanceOf(JWK.KeyMatchError);
  expect(error?._tag).toBe("JWKKeyMatchError");
  expect(error?.message).toBe("Multiple JWKs matched the given criteria");
});
