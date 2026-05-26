import { Effect } from "effect";
import { expect, it } from "vitest";

import { OAuth2PKCE } from "./pkce";

const minimumLengthCodeVerifier = "a".repeat(43);
const maximumLengthCodeVerifier = "a".repeat(128);
const rfc7636CodeVerifier = "dBjftJeZ4CVP-mB92K27uhbUJU1p1r_wW1gFWFOEjXk";
const rfc7636S256CodeChallenge = "E9Melhoa2OwvFrEMTJguCHaoeK1t8URWbuGJSstw-cM";

it("accepts a code verifier of exactly 43 characters", async () => {
  await expect(
    Effect.runPromise(
      OAuth2PKCE.validateCodeVerifier(minimumLengthCodeVerifier),
    ),
  ).resolves.toBeUndefined();
});

it("accepts a code verifier of exactly 128 characters", async () => {
  await expect(
    Effect.runPromise(
      OAuth2PKCE.validateCodeVerifier(maximumLengthCodeVerifier),
    ),
  ).resolves.toBeUndefined();
});

it("rejects code verifier lengths below 43 characters", async () => {
  const effect = Effect.match(OAuth2PKCE.validateCodeVerifier("a".repeat(42)), {
    onFailure: (error) => error,
    onSuccess: () => null,
  });

  const error = await Effect.runPromise(effect);

  expect(error).toBeInstanceOf(OAuth2PKCE.CodeVerifierValidationError);
  expect(error?._tag).toBe("CodeVerifierValidationError");
  expect(error?.message).toBe("Invalid PKCE code verifier length");
});

it("rejects code verifier lengths above 128 characters", async () => {
  const effect = Effect.match(
    OAuth2PKCE.validateCodeVerifier("a".repeat(129)),
    {
      onFailure: (error) => error,
      onSuccess: () => null,
    },
  );

  const error = await Effect.runPromise(effect);

  expect(error).toBeInstanceOf(OAuth2PKCE.CodeVerifierValidationError);
  expect(error?._tag).toBe("CodeVerifierValidationError");
  expect(error?.message).toBe("Invalid PKCE code verifier length");
});

it("rejects code verifiers containing invalid characters", async () => {
  const effect = Effect.match(
    OAuth2PKCE.validateCodeVerifier(`${minimumLengthCodeVerifier}!`),
    {
      onFailure: (error) => error,
      onSuccess: () => null,
    },
  );

  const error = await Effect.runPromise(effect);

  expect(error).toBeInstanceOf(OAuth2PKCE.CodeVerifierValidationError);
  expect(error?._tag).toBe("CodeVerifierValidationError");
  expect(error?.message).toBe("Invalid PKCE code verifier characters");
});

it("rejects empty code verifiers", async () => {
  const effect = Effect.match(OAuth2PKCE.validateCodeVerifier(""), {
    onFailure: (error) => error,
    onSuccess: () => null,
  });

  const error = await Effect.runPromise(effect);

  expect(error).toBeInstanceOf(OAuth2PKCE.CodeVerifierValidationError);
  expect(error?._tag).toBe("CodeVerifierValidationError");
  expect(error?.message).toBe("Invalid PKCE code verifier length");
});

it("creates a plain code challenge equal to the verifier", async () => {
  const codeChallenge = await Effect.runPromise(
    OAuth2PKCE.createCodeChallenge({
      codeVerifier: minimumLengthCodeVerifier,
      method: "plain",
    }),
  );

  expect(codeChallenge).toBe(minimumLengthCodeVerifier);
});

it("creates an S256 code challenge from a verifier", async () => {
  const codeChallenge = await Effect.runPromise(
    OAuth2PKCE.createCodeChallenge({
      codeVerifier: minimumLengthCodeVerifier,
      method: "S256",
    }),
  );

  expect(codeChallenge).toMatch(/^[A-Za-z0-9_-]+$/u);
  expect(codeChallenge).toHaveLength(43);
  expect(codeChallenge).not.toContain("=");
});

it("creates an S256 challenge using SHA-256", async () => {
  const codeChallenge = await Effect.runPromise(
    OAuth2PKCE.createCodeChallenge({
      codeVerifier: rfc7636CodeVerifier,
      method: "S256",
    }),
  );

  expect(codeChallenge).toBe(rfc7636S256CodeChallenge);
});

it("encodes S256 challenge using base64url without padding", async () => {
  const codeChallenge = await Effect.runPromise(
    OAuth2PKCE.createCodeChallenge({ codeVerifier: rfc7636CodeVerifier }),
  );

  expect(codeChallenge).toBe(rfc7636S256CodeChallenge);
  expect(codeChallenge).not.toContain("+");
  expect(codeChallenge).not.toContain("/");
  expect(codeChallenge).not.toContain("=");
});

it("rejects unsupported code challenge methods", async () => {
  const effect = Effect.match(
    OAuth2PKCE.createCodeChallenge({
      codeVerifier: minimumLengthCodeVerifier,
      method: "S512" as OAuth2PKCE.CodeChallengeMethod,
    }),
    {
      onFailure: (error) => error,
      onSuccess: () => null,
    },
  );

  const error = await Effect.runPromise(effect);

  expect(error).toBeInstanceOf(OAuth2PKCE.CodeChallengeMethodError);
  expect(error?._tag).toBe("CodeChallengeMethodError");
  expect(error?.message).toBe("Unsupported PKCE code challenge method");
  expect(error).toMatchObject({ method: "S512" });
});

it("rejects empty code challenge methods", async () => {
  const effect = Effect.match(
    OAuth2PKCE.createCodeChallenge({
      codeVerifier: minimumLengthCodeVerifier,
      method: "" as OAuth2PKCE.CodeChallengeMethod,
    }),
    {
      onFailure: (error) => error,
      onSuccess: () => null,
    },
  );

  const error = await Effect.runPromise(effect);

  expect(error).toBeInstanceOf(OAuth2PKCE.CodeChallengeMethodError);
  expect(error?._tag).toBe("CodeChallengeMethodError");
  expect(error?.message).toBe("Unsupported PKCE code challenge method");
  expect(error).toMatchObject({ method: "" });
});

it("defaults to S256 when no method is specified", async () => {
  const codeChallenge = await Effect.runPromise(
    OAuth2PKCE.createCodeChallenge({ codeVerifier: rfc7636CodeVerifier }),
  );

  expect(codeChallenge).toBe(rfc7636S256CodeChallenge);
});

it("validates a matching plain code challenge", async () => {
  await expect(
    Effect.runPromise(
      OAuth2PKCE.verifyCodeChallenge({
        codeChallenge: minimumLengthCodeVerifier,
        codeVerifier: minimumLengthCodeVerifier,
        method: "plain",
      }),
    ),
  ).resolves.toBeUndefined();
});

it("validates a matching S256 code challenge", async () => {
  await expect(
    Effect.runPromise(
      OAuth2PKCE.verifyCodeChallenge({
        codeChallenge: rfc7636S256CodeChallenge,
        codeVerifier: rfc7636CodeVerifier,
        method: "S256",
      }),
    ),
  ).resolves.toBeUndefined();
});

it("rejects a mismatched plain code challenge", async () => {
  const effect = Effect.match(
    OAuth2PKCE.verifyCodeChallenge({
      codeChallenge: maximumLengthCodeVerifier,
      codeVerifier: minimumLengthCodeVerifier,
      method: "plain",
    }),
    {
      onFailure: (error) => error,
      onSuccess: () => null,
    },
  );

  const error = await Effect.runPromise(effect);

  expect(error).toBeInstanceOf(OAuth2PKCE.CodeChallengeVerificationError);
  expect(error?._tag).toBe("CodeChallengeVerificationError");
  expect(error?.message).toBe("Invalid PKCE code challenge");
  expect(error).toMatchObject({ method: "plain" });
});

it("rejects a mismatched S256 code challenge", async () => {
  const effect = Effect.match(
    OAuth2PKCE.verifyCodeChallenge({
      codeChallenge: "invalid-code-challenge",
      codeVerifier: rfc7636CodeVerifier,
      method: "S256",
    }),
    {
      onFailure: (error) => error,
      onSuccess: () => null,
    },
  );

  const error = await Effect.runPromise(effect);

  expect(error).toBeInstanceOf(OAuth2PKCE.CodeChallengeVerificationError);
  expect(error?._tag).toBe("CodeChallengeVerificationError");
  expect(error?.message).toBe("Invalid PKCE code challenge");
  expect(error).toMatchObject({ method: "S256" });
});

it("matches the RFC 7636 S256 PKCE example", async () => {
  const codeChallenge = await Effect.runPromise(
    OAuth2PKCE.createCodeChallenge({
      codeVerifier: rfc7636CodeVerifier,
      method: "S256",
    }),
  );

  expect(codeChallenge).toBe(rfc7636S256CodeChallenge);
});
