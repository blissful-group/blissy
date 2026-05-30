import { Effect } from "effect";
import { expect, it } from "vitest";

import { OAuth2TokenIntrospectionResponse } from "./token-introspection-response";

it("parses inactive token introspection responses", async () => {
  const response = await Effect.runPromise(
    OAuth2TokenIntrospectionResponse.parse({ active: false }),
  );

  expect(response).toEqual({ active: false });
});

it("parses active token introspection responses", async () => {
  const response = await Effect.runPromise(
    OAuth2TokenIntrospectionResponse.parse({
      active: true,
      aud: ["api-1", "api-2"],
      client_id: "client-123",
      exp: 1_706_000_000,
      iat: 1_705_900_000,
      iss: "https://authorization-server.example",
      jti: "jwt-id-123",
      nbf: 1_705_900_000,
      scope: "read write read",
      sub: "user-123",
      token_type: "Bearer",
      username: "user@example.com",
    }),
  );

  expect(response).toEqual({
    active: true,
    aud: ["api-1", "api-2"],
    clientId: "client-123",
    exp: 1_706_000_000,
    iat: 1_705_900_000,
    iss: "https://authorization-server.example",
    jti: "jwt-id-123",
    nbf: 1_705_900_000,
    scope: ["read", "write"],
    sub: "user-123",
    tokenType: "Bearer",
    username: "user@example.com",
  });
});

it("parses active token introspection responses without optional claims", async () => {
  const response = await Effect.runPromise(
    OAuth2TokenIntrospectionResponse.parse({ active: true }),
  );

  expect(response).toEqual({ active: true });
});

it("parses string audience claims", async () => {
  const response = await Effect.runPromise(
    OAuth2TokenIntrospectionResponse.parse({
      active: true,
      aud: "api-1",
    }),
  );

  expect(response).toMatchObject({ aud: "api-1" });
});
