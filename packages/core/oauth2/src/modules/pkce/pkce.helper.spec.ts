import { Effect } from "effect";
import { expect, it } from "vitest";

import {
  CodeChallengeMethodError,
  CodeVerifierValidationError,
} from "./pkce.errors";
import { Helper } from "./pkce.helper";

it("base64url-encodes PKCE bytes", () => {
  expect(Helper.encodeBase64Url(new Uint8Array([251, 255]))).toBe("-_8");
});

it("validates code verifier length", async () => {
  await expect(
    Effect.runPromise(Helper.validateCodeVerifierLength("a".repeat(43))),
  ).resolves.toBe("a".repeat(43));
});

it("rejects invalid code verifier length", async () => {
  const effect = Effect.match(Helper.validateCodeVerifierLength("short"), {
    onFailure: (error) => error,
    onSuccess: () => null,
  });

  const error = await Effect.runPromise(effect);

  expect(error).toBeInstanceOf(CodeVerifierValidationError);
  expect(error?.message).toBe("Invalid PKCE code verifier length");
});

it("validates code verifier characters", async () => {
  await expect(
    Effect.runPromise(Helper.validateCodeVerifierCharacters("a".repeat(43))),
  ).resolves.toBe("a".repeat(43));
});

it("rejects invalid code verifier characters", async () => {
  const effect = Effect.match(
    Helper.validateCodeVerifierCharacters(`${"a".repeat(42)}!`),
    {
      onFailure: (error) => error,
      onSuccess: () => null,
    },
  );

  const error = await Effect.runPromise(effect);

  expect(error).toBeInstanceOf(CodeVerifierValidationError);
  expect(error?.message).toBe("Invalid PKCE code verifier characters");
});

it("validates supported code challenge methods", async () => {
  await Effect.runPromise(Helper.validateCodeChallengeMethod("S256"));
  await Effect.runPromise(Helper.validateCodeChallengeMethod("plain"));
});

it("rejects unsupported code challenge methods", async () => {
  const effect = Effect.match(Helper.validateCodeChallengeMethod("S512"), {
    onFailure: (error) => error,
    onSuccess: () => null,
  });

  const error = await Effect.runPromise(effect);

  expect(error).toBeInstanceOf(CodeChallengeMethodError);
  expect(error?._tag).toBe("CodeChallengeMethodError");
  expect(error?.message).toBe("Unsupported PKCE code challenge method");
});
