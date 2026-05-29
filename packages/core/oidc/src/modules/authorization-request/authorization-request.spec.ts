import { Effect } from "effect";
import { expect, it } from "vitest";

import { OIDCAuthorizationRequest } from "./authorization-request";

it("builds an authorization code request with openid scope", async () => {
  const effect = OIDCAuthorizationRequest.authorizationCode({
    authorizationEndpoint: "https://server.example/authorize",
    clientId: "client-123",
    nonce: "nonce-123",
    redirectUri: "https://client.example/callback",
    scope: ["profile", "email"],
    state: "state-123",
  });
  const url = await Effect.runPromise(effect);

  expect(url.searchParams.get("response_type")).toBe("code");
  expect(url.searchParams.get("client_id")).toBe("client-123");
  expect(url.searchParams.get("redirect_uri")).toBe(
    "https://client.example/callback",
  );
  expect(url.searchParams.get("scope")).toBe("openid profile email");
  expect(url.searchParams.get("state")).toBe("state-123");
  expect(url.searchParams.get("nonce")).toBe("nonce-123");
});

it("does not duplicate openid scope", async () => {
  const effect = OIDCAuthorizationRequest.authorizationCode({
    authorizationEndpoint: "https://server.example/authorize",
    clientId: "client-123",
    redirectUri: "https://client.example/callback",
    scope: ["openid", "profile"],
  });
  const url = await Effect.runPromise(effect);

  expect(url.searchParams.get("scope")).toBe("openid profile");
});

it("supports PKCE parameters", async () => {
  const effect = OIDCAuthorizationRequest.authorizationCode({
    authorizationEndpoint: "https://server.example/authorize",
    clientId: "client-123",
    codeChallenge: "challenge-123",
    codeChallengeMethod: "S256",
    redirectUri: "https://client.example/callback",
  });
  const url = await Effect.runPromise(effect);

  expect(url.searchParams.get("code_challenge")).toBe("challenge-123");
  expect(url.searchParams.get("code_challenge_method")).toBe("S256");
});

it("rejects nonce as a custom parameter", async () => {
  const effect = Effect.match(
    OIDCAuthorizationRequest.authorizationCode({
      authorizationEndpoint: "https://server.example/authorize",
      clientId: "client-123",
      parameters: { nonce: "custom" },
      redirectUri: "https://client.example/callback",
    }),
    {
      onFailure: (error) => error,
      onSuccess: () => null,
    },
  );

  const error = (await Effect.runPromise(effect)) as InstanceType<
    typeof OIDCAuthorizationRequest.ValidationError
  > | null;

  expect(error).toBeInstanceOf(OIDCAuthorizationRequest.ValidationError);
  expect(error?._tag).toBe("OIDCAuthorizationRequestValidationError");
  expect(error).toMatchObject({ parameter: "nonce" });
});
