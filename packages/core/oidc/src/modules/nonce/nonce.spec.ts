import { CryptoReference } from "@blissy-auth/crypto";
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
