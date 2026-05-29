import { Effect } from "effect";
import { expect, it } from "vitest";

import { OIDCIDTokenValidationError } from "./id-token.errors";
import { Helper } from "./id-token.helper";

it("validates ID token issuers", async () => {
  const effect = Effect.match(
    Helper.validateIssuer({
      claims: { iss: "https://other.example" },
      issuer: "https://issuer.example",
    }),
    {
      onFailure: (error) => error,
      onSuccess: () => null,
    },
  );

  const error = await Effect.runPromise(effect);

  expect(error).toBeInstanceOf(OIDCIDTokenValidationError);
  expect(error?._tag).toBe("OIDCIDTokenValidationError");
  expect(error?.message).toBe("Invalid ID token issuer");
});

it("accepts valid ID token issuers", async () => {
  await Effect.runPromise(
    Helper.validateIssuer({
      claims: { iss: "https://issuer.example" },
      issuer: "https://issuer.example",
    }),
  );
});

it("rejects missing ID token issuers", async () => {
  const effect = Effect.match(Helper.validateIssuer({ claims: {} }), {
    onFailure: (error) => error,
    onSuccess: () => null,
  });

  const error = await Effect.runPromise(effect);

  expect(error).toBeInstanceOf(OIDCIDTokenValidationError);
  expect(error?.message).toBe("Invalid ID token issuer");
});

it("validates ID token subjects", async () => {
  await Effect.runPromise(Helper.validateSubject({ sub: "user-123" }));
});

it("rejects invalid ID token subjects", async () => {
  const effect = Effect.match(Helper.validateSubject({}), {
    onFailure: (error) => error,
    onSuccess: () => null,
  });

  const error = await Effect.runPromise(effect);

  expect(error).toBeInstanceOf(OIDCIDTokenValidationError);
  expect(error?.message).toBe("Invalid ID token subject");
});

it("validates ID token audiences", async () => {
  await Effect.runPromise(
    Helper.validateAudience({
      audience: "api",
      claims: { aud: ["api"], azp: "api" },
    }),
  );
});

it("validates authorized parties for multiple ID token audiences", async () => {
  await Effect.runPromise(
    Helper.validateAudience({
      audience: "api",
      claims: { aud: ["api", "web"], azp: "api" },
    }),
  );
});

it("rejects invalid ID token audiences", async () => {
  const effect = Effect.match(
    Helper.validateAudience({ audience: "api", claims: { aud: ["web"] } }),
    {
      onFailure: (error) => error,
      onSuccess: () => null,
    },
  );

  const error = await Effect.runPromise(effect);

  expect(error).toBeInstanceOf(OIDCIDTokenValidationError);
  expect(error?.message).toBe("Invalid ID token audience");
});

it("rejects structurally invalid ID token audiences", async () => {
  const effect = Effect.match(Helper.validateAudience({ claims: {} }), {
    onFailure: (error) => error,
    onSuccess: () => null,
  });

  const error = await Effect.runPromise(effect);

  expect(error).toBeInstanceOf(OIDCIDTokenValidationError);
  expect(error?.message).toBe("Invalid ID token audience");
});

it("requires azp for multiple ID token audiences", async () => {
  const effect = Effect.match(
    Helper.validateAudience({
      audience: "api",
      claims: { aud: ["api", "web"] },
    }),
    {
      onFailure: (error) => error,
      onSuccess: () => null,
    },
  );

  const error = await Effect.runPromise(effect);

  expect(error).toBeInstanceOf(OIDCIDTokenValidationError);
  expect(error?.message).toBe("Invalid ID token authorized party");
});

it("validates ID token expiration", async () => {
  await Effect.runPromise(Helper.validateExpiration({ exp: 1 }));
});

it("rejects invalid ID token expiration", async () => {
  const effect = Effect.match(Helper.validateExpiration({}), {
    onFailure: (error) => error,
    onSuccess: () => null,
  });

  const error = await Effect.runPromise(effect);

  expect(error).toBeInstanceOf(OIDCIDTokenValidationError);
  expect(error?.message).toBe("Invalid ID token expiration");
});

it("validates ID token issued-at", async () => {
  await Effect.runPromise(Helper.validateIssuedAt({ iat: 1 }));
});

it("rejects invalid ID token issued-at", async () => {
  const effect = Effect.match(Helper.validateIssuedAt({}), {
    onFailure: (error) => error,
    onSuccess: () => null,
  });

  const error = await Effect.runPromise(effect);

  expect(error).toBeInstanceOf(OIDCIDTokenValidationError);
  expect(error?.message).toBe("Invalid ID token issued at");
});

it("accepts matching ID token nonce", async () => {
  await Effect.runPromise(
    Helper.validateNonce({
      claims: { nonce: "nonce" },
      expectedNonce: "nonce",
    }),
  );
});

it("accepts missing expected ID token nonce", async () => {
  await Effect.runPromise(Helper.validateNonce({ claims: {} }));
});

it("rejects non-string ID token nonce", async () => {
  const effect = Effect.match(
    Helper.validateNonce({ claims: {}, expectedNonce: "expected" }),
    {
      onFailure: (error) => error,
      onSuccess: () => null,
    },
  );

  const error = await Effect.runPromise(effect);

  expect(error).toBeInstanceOf(OIDCIDTokenValidationError);
  expect(error?.message).toBe("Invalid ID token nonce");
});

it("validates ID token nonce", async () => {
  const effect = Effect.match(
    Helper.validateNonce({
      claims: { nonce: "actual" },
      expectedNonce: "expected",
    }),
    {
      onFailure: (error) => error,
      onSuccess: () => null,
    },
  );

  const error = await Effect.runPromise(effect);

  expect(error).toBeInstanceOf(OIDCIDTokenValidationError);
  expect(error?._tag).toBe("OIDCIDTokenValidationError");
  expect(error?.message).toBe("Invalid ID token nonce");
});

it("fails with ID token validation errors", async () => {
  const effect = Effect.match(Helper.fail("Invalid ID token issuer"), {
    onFailure: (error) => error,
    onSuccess: () => null,
  });

  const error = await Effect.runPromise(effect);

  expect(error).toBeInstanceOf(OIDCIDTokenValidationError);
  expect(error?.message).toBe("Invalid ID token issuer");
});
