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

it("imports an RSA verification key", async () => {
  const keyPair = await crypto.subtle.generateKey(
    {
      hash: "SHA-256",
      modulusLength: 2048,
      name: "RSASSA-PKCS1-v1_5",
      publicExponent: new Uint8Array([1, 0, 1]),
    },
    true,
    ["sign", "verify"],
  );
  const jwk = await crypto.subtle.exportKey("jwk", keyPair.publicKey);

  const key = await Effect.runPromise(
    JWK.importVerificationKey({
      ...jwk,
      alg: "RS256",
      kid: "sig-1",
    } as JWK.Key),
  );

  expect(key).toBeInstanceOf(CryptoKey);
  expect(key.algorithm.name).toBe("RSASSA-PKCS1-v1_5");
  expect(key.usages).toEqual(["verify"]);
});

it("imports an EC verification key", async () => {
  const keyPair = await crypto.subtle.generateKey(
    {
      name: "ECDSA",
      namedCurve: "P-256",
    },
    true,
    ["sign", "verify"],
  );
  const jwk = await crypto.subtle.exportKey("jwk", keyPair.publicKey);

  const key = await Effect.runPromise(
    JWK.importVerificationKey({
      ...jwk,
      alg: "ES256",
      kid: "sig-1",
    } as JWK.Key),
  );

  expect(key).toBeInstanceOf(CryptoKey);
  expect(key.algorithm.name).toBe("ECDSA");
  expect(key.usages).toEqual(["verify"]);
});

it("rejects unsupported verification keys", async () => {
  const effect = Effect.match(
    JWK.importVerificationKey({ k: "secret", kty: "oct" }),
    {
      onFailure: (error) => error,
      onSuccess: () => null,
    },
  );

  const error = await Effect.runPromise(effect);

  expect(error).toBeInstanceOf(JWK.KeyImportError);
  expect(error?._tag).toBe("JWKKeyImportError");
  expect(error?.message).toBe("Invalid JWK key");
});

it("rejects malformed verification keys", async () => {
  const effect = Effect.match(
    JWK.importVerificationKey({ e: "AQAB", kty: "RSA" }),
    {
      onFailure: (error) => error,
      onSuccess: () => null,
    },
  );

  const error = await Effect.runPromise(effect);

  expect(error).toBeInstanceOf(JWK.KeyImportError);
  expect(error?._tag).toBe("JWKKeyImportError");
  expect(error?.message).toBe("Invalid JWK key");
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
