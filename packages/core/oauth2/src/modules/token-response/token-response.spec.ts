import { Effect } from "effect";
import { expect, it } from "vitest";

import { OAuth2TokenResponse } from "./token-response";

it("parses a successful access token response", async () => {
  const response = await Effect.runPromise(
    OAuth2TokenResponse.parse({
      access_token: "access-123",
      token_type: "Bearer",
    }),
  );

  expect(response).toEqual({
    accessToken: "access-123",
    expiresIn: undefined,
    refreshToken: undefined,
    scope: undefined,
    tokenType: "Bearer",
    type: "success",
  });
});

it("parses optional successful token response fields", async () => {
  const response = await Effect.runPromise(
    OAuth2TokenResponse.parse({
      access_token: "access-123",
      expires_in: 3600,
      refresh_token: "refresh-123",
      scope: "read write read",
      token_type: "Bearer",
    }),
  );

  expect(response).toMatchObject({
    accessToken: "access-123",
    expiresIn: 3600,
    refreshToken: "refresh-123",
    scope: ["read", "write"],
    type: "success",
  });
});

it("rejects invalid scope values", async () => {
  const effect = Effect.match(
    OAuth2TokenResponse.parse({
      access_token: "access-123",
      scope: "invalid\\scope",
      token_type: "Bearer",
    }),
    {
      onFailure: (error) => error,
      onSuccess: () => null,
    },
  );

  const error = await Effect.runPromise(effect);

  expect(error?._tag).toBe("OAuth2ScopeValidationError");
});

it("parses a token error response", async () => {
  const response = await Effect.runPromise(
    OAuth2TokenResponse.parse({
      error: "invalid_grant",
      error_description: "Code expired",
      error_uri: "https://authorization-server.example/errors/invalid_grant",
    }),
  );

  expect(response).toEqual({
    error: "invalid_grant",
    errorDescription: "Code expired",
    errorUri: new URL(
      "https://authorization-server.example/errors/invalid_grant",
    ),
    type: "error",
  });
});

it("parses a token error response without optional fields", async () => {
  const response = await Effect.runPromise(
    OAuth2TokenResponse.parse({
      error: "invalid_grant",
    }),
  );

  expect(response).toEqual({
    error: "invalid_grant",
    errorDescription: undefined,
    errorUri: undefined,
    type: "error",
  });
});

it("rejects structurally invalid error_uri values", async () => {
  const effect = Effect.match(
    OAuth2TokenResponse.parse({
      error: "invalid_grant",
      error_uri: "not-a-url",
    }),
    {
      onFailure: (error) => error,
      onSuccess: () => null,
    },
  );

  const error = await Effect.runPromise(effect);

  expect(error).toBeInstanceOf(OAuth2TokenResponse.ValidationError);
  expect(error?.message).toBe("Invalid token error URI");
});
