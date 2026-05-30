import { JWT } from "@blissy-auth/jose";
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
