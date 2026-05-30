import { AlgorithmReference, CryptoReference } from "@blissy-auth/crypto";
import { Effect } from "effect";
import { expect, it } from "vitest";

import { OAuth2PKCE } from "./pkce";

const minimumLengthCodeVerifier = "a".repeat(43);
const maximumLengthCodeVerifier = "a".repeat(128);
const rfc7636CodeVerifier = "dBjftJeZ4CVP-mB92K27uhbUJU1p1r_wW1gFWFOEjXk";
const rfc7636S256CodeChallenge = "E9Melhoa2OwvFrEMTJguCHaoeK1t8URWbuGJSstw-cM";
const cryptoService = CryptoReference.defaultValue();

it("generates a non-empty code verifier", async () => {
  const codeVerifier = await Effect.runPromise(
    OAuth2PKCE.generateCodeVerifier(),
  );

  expect(codeVerifier).not.toBe("");
});

it("generates URL-safe code verifier values", async () => {
  const codeVerifier = await Effect.runPromise(
    OAuth2PKCE.generateCodeVerifier(),
  );

  expect(codeVerifier).toMatch(/^[A-Za-z0-9._~-]+$/u);
});

it("generates code verifiers with the default valid length", async () => {
  const codeVerifier = await Effect.runPromise(
    OAuth2PKCE.generateCodeVerifier(),
  );

  expect(codeVerifier).toHaveLength(43);
});

it("supports configurable code verifier length", async () => {
  const codeVerifier = await Effect.runPromise(
    OAuth2PKCE.generateCodeVerifier({ byteLength: 96 }),
  );

  expect(codeVerifier).toHaveLength(128);
});

it("supports dependency injection for randomness", async () => {
  const service = Effect.provideService(CryptoReference, {
    ...cryptoService,
    randomValues(bytes) {
      bytes.fill(0);

      return bytes;
    },
  });
  const effect = OAuth2PKCE.generateCodeVerifier().pipe(service);
  const codeVerifier = await Effect.runPromise(effect);

  expect(codeVerifier).toBe("AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA");
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

it("supports dependency injection for crypto", async () => {
  const digestInput: Array<{
    algorithm: AlgorithmIdentifier;
    data: string;
  }> = [];
  const service = Effect.provideService(CryptoReference, {
    ...cryptoService,
    digest: (algorithm, data) => {
      digestInput.push({
        algorithm,
        data: new TextDecoder().decode(data),
      });

      return Promise.resolve(new Uint8Array(32).buffer);
    },
  });
  const effect = OAuth2PKCE.createCodeChallenge({
    codeVerifier: minimumLengthCodeVerifier,
    method: "S256",
  }).pipe(service);
  const codeChallenge = await Effect.runPromise(effect);

  expect(digestInput).toEqual([
    {
      algorithm: "SHA-256",
      data: minimumLengthCodeVerifier,
    },
  ]);
  expect(codeChallenge).toBe("AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA");
});

it("supports dependency injection for algorithms", async () => {
  const digestInput: AlgorithmIdentifier[] = [];
  const cryptoServiceWithDigest = {
    ...cryptoService,
    digest: (algorithm: AlgorithmIdentifier) => {
      digestInput.push(algorithm);

      return Promise.resolve(new Uint8Array(32).buffer);
    },
  };
  const algorithmService = Effect.provideService(AlgorithmReference, {
    ...AlgorithmReference.defaultValue(),
    digest: { [AlgorithmReference.SHA256]: "SHA-512" },
  });
  const cryptoServiceProvider = Effect.provideService(
    CryptoReference,
    cryptoServiceWithDigest,
  );
  const effect = OAuth2PKCE.createCodeChallenge({
    codeVerifier: minimumLengthCodeVerifier,
    method: "S256",
  }).pipe(algorithmService, cryptoServiceProvider);

  await Effect.runPromise(effect);

  expect(digestInput).toEqual(["SHA-512"]);
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
