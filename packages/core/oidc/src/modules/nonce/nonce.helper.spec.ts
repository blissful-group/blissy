import { Effect } from "effect";
import { expect, it } from "vitest";

import {
  OIDCNonceGenerationError,
  OIDCNonceValidationError,
} from "./nonce.errors";
import { Helper } from "./nonce.helper";

it("base64url-encodes nonce bytes", () => {
  expect(Helper.encodeBase64Url(new Uint8Array([251, 255]))).toBe("-_8");
});

it("validates nonce byte length", async () => {
  await expect(Effect.runPromise(Helper.validateByteLength(32))).resolves.toBe(
    32,
  );
});

it("rejects invalid nonce byte length", async () => {
  const effect = Effect.match(Helper.validateByteLength(0), {
    onFailure: (error) => error,
    onSuccess: () => null,
  });

  const error = await Effect.runPromise(effect);

  expect(error).toBeInstanceOf(OIDCNonceGenerationError);
  expect(error?.message).toBe("Invalid OIDC nonce byte length");
});

it("validates expected nonce", async () => {
  await Effect.runPromise(Helper.validateExpectedNonce("nonce"));
});

it("rejects missing expected nonce", async () => {
  const effect = Effect.match(Helper.validateExpectedNonce(""), {
    onFailure: (error) => error,
    onSuccess: () => null,
  });

  const error = await Effect.runPromise(effect);

  expect(error).toBeInstanceOf(OIDCNonceValidationError);
  expect(error?.message).toBe("Missing OIDC nonce");
});

it("validates returned nonce", async () => {
  await Effect.runPromise(Helper.validateReturnedNonce("nonce"));
});

it("rejects missing returned nonce", async () => {
  const effect = Effect.match(Helper.validateReturnedNonce(""), {
    onFailure: (error) => error,
    onSuccess: () => null,
  });

  const error = await Effect.runPromise(effect);

  expect(error).toBeInstanceOf(OIDCNonceValidationError);
  expect(error?.message).toBe("Missing OIDC nonce");
});

it("validates matching nonces", async () => {
  await Effect.runPromise(
    Helper.validateNonceMatch({
      expectedNonce: "nonce",
      returnedNonce: "nonce",
    }),
  );
});

it("rejects mismatched nonces", async () => {
  const effect = Effect.match(
    Helper.validateNonceMatch({
      expectedNonce: "expected",
      returnedNonce: "actual",
    }),
    {
      onFailure: (error) => error,
      onSuccess: () => null,
    },
  );

  const error = await Effect.runPromise(effect);

  expect(error).toBeInstanceOf(OIDCNonceValidationError);
  expect(error?._tag).toBe("OIDCNonceValidationError");
  expect(error?.message).toBe("Invalid OIDC nonce");
});
