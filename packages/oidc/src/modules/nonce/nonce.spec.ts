import { CryptoReference } from "@blissy-auth/crypto/source";
import { Effect } from "effect";
import { expect, it } from "vitest";

import { OIDCNonce } from "./nonce";

const cryptoService = CryptoReference.defaultValue();

it("generates a non-empty nonce value", async () => {
  const nonce = await Effect.runPromise(OIDCNonce.generate());

  expect(nonce).not.toBe("");
});

it("generates URL-safe nonce values", async () => {
  const nonce = await Effect.runPromise(OIDCNonce.generate());

  expect(nonce).toMatch(/^[A-Za-z0-9_-]+$/u);
  expect(nonce).not.toContain("=");
});

it("generates different nonce values across calls", async () => {
  const firstNonce = await Effect.runPromise(OIDCNonce.generate());
  const secondNonce = await Effect.runPromise(OIDCNonce.generate());

  expect(firstNonce).not.toBe(secondNonce);
});

it("supports configurable nonce byte length", async () => {
  const nonce = await Effect.runPromise(OIDCNonce.generate(16));

  expect(nonce).toHaveLength(22);
});

it("supports dependency injection for randomness", async () => {
  const service = Effect.provideService(CryptoReference, {
    ...cryptoService,
    randomValues: (bytes) => {
      bytes.set([0xff, 0xee, 0xdd, 0xcc]);

      return bytes;
    },
  });
  const effect = OIDCNonce.generate(4).pipe(service);
  const nonce = await Effect.runPromise(effect);

  expect(nonce).toBe("_-7dzA");
});

it("rejects nonce generation with zero length", async () => {
  const effect = Effect.match(OIDCNonce.generate(0), {
    onFailure: (error) => error,
    onSuccess: () => null,
  });

  const error = await Effect.runPromise(effect);

  expect(error).toBeInstanceOf(OIDCNonce.GenerationError);
  expect(error?._tag).toBe("OIDCNonceGenerationError");
  expect(error?.message).toBe("Invalid OIDC nonce byte length");
  expect(error).toMatchObject({ byteLength: 0 });
});

it("rejects nonce generation with fractional length", async () => {
  const effect = Effect.match(OIDCNonce.generate(1.5), {
    onFailure: (error) => error,
    onSuccess: () => null,
  });

  const error = await Effect.runPromise(effect);

  expect(error).toBeInstanceOf(OIDCNonce.GenerationError);
  expect(error?._tag).toBe("OIDCNonceGenerationError");
  expect(error?.message).toBe("Invalid OIDC nonce byte length");
  expect(error).toMatchObject({ byteLength: 1.5 });
});

it("validates matching nonce values", async () => {
  await expect(
    Effect.runPromise(
      OIDCNonce.validate({
        expectedNonce: "nonce-123",
        returnedNonce: "nonce-123",
      }),
    ),
  ).resolves.toBeUndefined();
});

it("rejects missing expected nonce", async () => {
  const effect = Effect.match(
    OIDCNonce.validate({ returnedNonce: "nonce-123" }),
    {
      onFailure: (error) => error,
      onSuccess: () => null,
    },
  );

  const error = await Effect.runPromise(effect);

  expect(error).toBeInstanceOf(OIDCNonce.ValidationError);
  expect(error?._tag).toBe("OIDCNonceValidationError");
  expect(error?.message).toBe("Missing OIDC nonce");
});

it("rejects missing returned nonce", async () => {
  const effect = Effect.match(
    OIDCNonce.validate({ expectedNonce: "nonce-123" }),
    {
      onFailure: (error) => error,
      onSuccess: () => null,
    },
  );

  const error = await Effect.runPromise(effect);

  expect(error).toBeInstanceOf(OIDCNonce.ValidationError);
  expect(error?._tag).toBe("OIDCNonceValidationError");
  expect(error?.message).toBe("Missing OIDC nonce");
});

it("rejects mismatched nonce values", async () => {
  const effect = Effect.match(
    OIDCNonce.validate({
      expectedNonce: "nonce-123",
      returnedNonce: "nonce-456",
    }),
    {
      onFailure: (error) => error,
      onSuccess: () => null,
    },
  );

  const error = await Effect.runPromise(effect);

  expect(error).toBeInstanceOf(OIDCNonce.ValidationError);
  expect(error?._tag).toBe("OIDCNonceValidationError");
  expect(error?.message).toBe("Invalid OIDC nonce");
});
