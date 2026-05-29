import { CryptoReference } from "@blissy-auth/crypto/source";
import { Effect } from "effect";
import { expect, it } from "vitest";

import { JWA } from "./jwa";

const encoder = new TextEncoder();
const payload = encoder.encode("hello world");
const cryptoService = CryptoReference.defaultValue();

it("signs and verifies with HS256", async () => {
  const key = encoder.encode("super-secret-signing-key");
  const signature = await Effect.runPromise(
    JWA.sign({
      alg: "HS256",
      key,
      payload,
    }),
  );

  const valid = await Effect.runPromise(
    JWA.verify({
      alg: "HS256",
      key,
      payload,
      signature,
    }),
  );

  expect(signature).toBeInstanceOf(Uint8Array);
  expect(signature.length).toBeGreaterThan(0);
  expect(valid).toBe(true);
});

it("signs and verifies with RS256", async () => {
  const keyPair = await crypto.subtle.generateKey(
    {
      name: "RSASSA-PKCS1-v1_5",
      hash: "SHA-256",
      modulusLength: 2048,
      publicExponent: new Uint8Array([1, 0, 1]),
    },
    true,
    ["sign", "verify"],
  );
  const signature = await Effect.runPromise(
    JWA.sign({
      alg: "RS256",
      key: keyPair.privateKey,
      payload,
    }),
  );

  const valid = await Effect.runPromise(
    JWA.verify({
      alg: "RS256",
      key: keyPair.publicKey,
      payload,
      signature,
    }),
  );

  expect(signature).toBeInstanceOf(Uint8Array);
  expect(signature.length).toBeGreaterThan(0);
  expect(valid).toBe(true);
});

it("supports dependency injection for signing", async () => {
  const keyPair = await crypto.subtle.generateKey(
    {
      name: "RSASSA-PKCS1-v1_5",
      hash: "SHA-256",
      modulusLength: 2048,
      publicExponent: new Uint8Array([1, 0, 1]),
    },
    true,
    ["sign", "verify"],
  );
  const service = Effect.provideService(CryptoReference, {
    ...cryptoService,
    sign: () => Promise.resolve(new Uint8Array([1, 2, 3]).buffer),
  });

  const signature = await Effect.runPromise(
    JWA.sign({
      alg: "RS256",
      key: keyPair.privateKey,
      payload,
    }).pipe(service),
  );

  expect(signature).toEqual(new Uint8Array([1, 2, 3]));
});

it("signs and verifies with ES256", async () => {
  const keyPair = await crypto.subtle.generateKey(
    {
      name: "ECDSA",
      namedCurve: "P-256",
    },
    true,
    ["sign", "verify"],
  );
  const signature = await Effect.runPromise(
    JWA.sign({
      alg: "ES256",
      key: keyPair.privateKey,
      payload,
    }),
  );

  const valid = await Effect.runPromise(
    JWA.verify({
      alg: "ES256",
      key: keyPair.publicKey,
      payload,
      signature,
    }),
  );

  expect(signature).toBeInstanceOf(Uint8Array);
  expect(signature.length).toBeGreaterThan(0);
  expect(valid).toBe(true);
});

it("rejects unsupported algorithms", async () => {
  const effect = Effect.match(
    JWA.sign({
      alg: "PS256" as JWA.Algorithm,
      key: encoder.encode("super-secret-signing-key"),
      payload,
    }),
    {
      onFailure: (error) => error,
      onSuccess: () => null,
    },
  );

  const error = await Effect.runPromise(effect);

  expect(error).toBeInstanceOf(JWA.AlgorithmNotSupportedError);
  expect(error?._tag).toBe("JWAAlgorithmNotSupportedError");
  expect(error?.message).toBe('Unsupported JWA algorithm: "PS256"');
});

it("rejects keys incompatible with the selected algorithm", async () => {
  const effect = Effect.match(
    JWA.sign({
      alg: "RS256",
      key: encoder.encode("super-secret-signing-key"),
      payload,
    }),
    {
      onFailure: (error) => error,
      onSuccess: () => null,
    },
  );

  const error = await Effect.runPromise(effect);

  expect(error).toBeInstanceOf(JWA.KeyCompatibilityError);
  expect(error?._tag).toBe("JWAKeyCompatibilityError");
  expect(error?.message).toBe(
    'Key is incompatible with JWA algorithm: "RS256"',
  );
});
