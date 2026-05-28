import { JWT } from "@blissy-auth/jose/source";
import { Effect } from "effect";
import { expect, it } from "vitest";

import { OIDCIDToken } from "./id-token";

const encoder = new TextEncoder();
const key = encoder.encode("super-secret-signing-key");
const now = 1_700_000_000;

it("decodes an ID token and validates required OIDC claims", async () => {
  const claims: JWT.Claims = {
    aud: "client-123",
    exp: now + 60,
    iat: now - 10,
    iss: "https://server.example",
    nonce: "nonce-123",
    sub: "user-123",
  };
  const token = await Effect.runPromise(JWT.sign({ claims, key }));

  const decoded = await Effect.runPromise(OIDCIDToken.decode({ token }));

  expect(decoded.claims).toEqual(claims);
});

it("verifies an ID token", async () => {
  const claims: JWT.Claims = {
    aud: "client-123",
    exp: now + 60,
    iat: now - 10,
    iss: "https://server.example",
    nonce: "nonce-123",
    sub: "user-123",
  };
  const token = await Effect.runPromise(JWT.sign({ claims, key }));

  const decoded = await Effect.runPromise(
    OIDCIDToken.verify({
      audience: "client-123",
      expectedNonce: "nonce-123",
      issuer: "https://server.example",
      key,
      now,
      token,
    }),
  );

  expect(decoded.claims).toEqual(claims);
});

it("rejects an ID token with a missing subject", async () => {
  const claims: JWT.Claims = {
    aud: "client-123",
    exp: now + 60,
    iat: now - 10,
    iss: "https://server.example",
    nonce: "nonce-123",
  };
  const token = await Effect.runPromise(JWT.sign({ claims, key }));
  const effect = Effect.match(OIDCIDToken.decode({ token }), {
    onFailure: (error) => error,
    onSuccess: () => null,
  });

  const error = (await Effect.runPromise(effect)) as InstanceType<
    typeof OIDCIDToken.ValidationError
  > | null;

  expect(error).toBeInstanceOf(OIDCIDToken.ValidationError);
  expect(error?._tag).toBe("OIDCIDTokenValidationError");
  expect(error?.message).toBe("Invalid ID token subject");
});

it("rejects an ID token with an invalid nonce", async () => {
  const claims: JWT.Claims = {
    aud: "client-123",
    exp: now + 60,
    iat: now - 10,
    iss: "https://server.example",
    nonce: "nonce-456",
    sub: "user-123",
  };
  const token = await Effect.runPromise(JWT.sign({ claims, key }));
  const effect = Effect.match(
    OIDCIDToken.verify({
      audience: "client-123",
      expectedNonce: "nonce-123",
      issuer: "https://server.example",
      key,
      now,
      token,
    }),
    {
      onFailure: (error) => error,
      onSuccess: () => null,
    },
  );

  const error = (await Effect.runPromise(effect)) as InstanceType<
    typeof OIDCIDToken.ValidationError
  > | null;

  expect(error).toBeInstanceOf(OIDCIDToken.ValidationError);
  expect(error?.message).toBe("Invalid ID token nonce");
});

it("requires azp when the ID token has multiple audiences", async () => {
  const claims: JWT.Claims = {
    aud: ["client-123", "api"],
    exp: now + 60,
    iat: now - 10,
    iss: "https://server.example",
    nonce: "nonce-123",
    sub: "user-123",
  };
  const token = await Effect.runPromise(JWT.sign({ claims, key }));
  const effect = Effect.match(
    OIDCIDToken.verify({
      audience: "client-123",
      issuer: "https://server.example",
      key,
      now,
      token,
    }),
    {
      onFailure: (error) => error,
      onSuccess: () => null,
    },
  );

  const error = (await Effect.runPromise(effect)) as InstanceType<
    typeof OIDCIDToken.ValidationError
  > | null;

  expect(error).toBeInstanceOf(OIDCIDToken.ValidationError);
  expect(error?.message).toBe("Invalid ID token authorized party");
});
