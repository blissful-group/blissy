import { Effect } from "effect";
import { expect, it } from "vitest";

import { OAuth2AuthorizationRequest } from "./authorization-request";

const authorizationEndpoint = "https://authorization-server.example/authorize";
const clientId = "client-123";
const redirectUri = "https://client.example/callback";

it("builds an authorization code request URL", async () => {
  const url = await Effect.runPromise(
    OAuth2AuthorizationRequest.authorizationCode({
      authorizationEndpoint,
      clientId,
      redirectUri,
    }),
  );

  expect(url).toBeInstanceOf(URL);
  expect(url.origin).toBe("https://authorization-server.example");
  expect(url.pathname).toBe("/authorize");
});

it("includes response_type=code", async () => {
  const url = await Effect.runPromise(
    OAuth2AuthorizationRequest.authorizationCode({
      authorizationEndpoint,
      clientId,
      redirectUri,
    }),
  );

  expect(url.searchParams.get("response_type")).toBe("code");
});

it("includes client_id", async () => {
  const url = await Effect.runPromise(
    OAuth2AuthorizationRequest.authorizationCode({
      authorizationEndpoint,
      clientId,
      redirectUri,
    }),
  );

  expect(url.searchParams.get("client_id")).toBe(clientId);
});

it("includes redirect_uri", async () => {
  const url = await Effect.runPromise(
    OAuth2AuthorizationRequest.authorizationCode({
      authorizationEndpoint,
      clientId,
      redirectUri,
    }),
  );

  expect(url.searchParams.get("redirect_uri")).toBe(redirectUri);
});

it("includes scope when provided", async () => {
  const url = await Effect.runPromise(
    OAuth2AuthorizationRequest.authorizationCode({
      authorizationEndpoint,
      clientId,
      redirectUri,
      scope: ["openid", "profile", "profile"],
    }),
  );

  expect(url.searchParams.get("scope")).toBe("openid profile");
});

it("includes state when provided", async () => {
  const url = await Effect.runPromise(
    OAuth2AuthorizationRequest.authorizationCode({
      authorizationEndpoint,
      clientId,
      redirectUri,
      state: "state-123",
    }),
  );

  expect(url.searchParams.get("state")).toBe("state-123");
});

it("includes code_challenge when provided", async () => {
  const url = await Effect.runPromise(
    OAuth2AuthorizationRequest.authorizationCode({
      authorizationEndpoint,
      clientId,
      codeChallenge: "challenge-123",
      redirectUri,
    }),
  );

  expect(url.searchParams.get("code_challenge")).toBe("challenge-123");
});

it("includes code_challenge_method when provided", async () => {
  const url = await Effect.runPromise(
    OAuth2AuthorizationRequest.authorizationCode({
      authorizationEndpoint,
      clientId,
      codeChallenge: "challenge-123",
      codeChallengeMethod: "S256",
      redirectUri,
    }),
  );

  expect(url.searchParams.get("code_challenge_method")).toBe("S256");
});

it("omits optional parameters when they are not provided", async () => {
  const url = await Effect.runPromise(
    OAuth2AuthorizationRequest.authorizationCode({
      authorizationEndpoint,
      clientId,
      redirectUri,
    }),
  );

  expect(url.searchParams.has("scope")).toBe(false);
  expect(url.searchParams.has("state")).toBe(false);
  expect(url.searchParams.has("code_challenge")).toBe(false);
  expect(url.searchParams.has("code_challenge_method")).toBe(false);
});

it("preserves existing authorization endpoint query parameters", async () => {
  const url = await Effect.runPromise(
    OAuth2AuthorizationRequest.authorizationCode({
      authorizationEndpoint: `${authorizationEndpoint}?tenant=primary`,
      clientId,
      redirectUri,
    }),
  );

  expect(url.searchParams.get("tenant")).toBe("primary");
});

it("URL-encodes query parameter values", async () => {
  const url = await Effect.runPromise(
    OAuth2AuthorizationRequest.authorizationCode({
      authorizationEndpoint,
      clientId: "client id",
      redirectUri: "https://client.example/callback?next=/dashboard",
      state: "state with spaces",
    }),
  );

  expect(url.toString()).toContain("client_id=client+id");
  expect(url.toString()).toContain(
    "redirect_uri=https%3A%2F%2Fclient.example%2Fcallback%3Fnext%3D%2Fdashboard",
  );
  expect(url.toString()).toContain("state=state+with+spaces");
});

it("rejects an invalid authorization endpoint URL", async () => {
  const effect = Effect.match(
    OAuth2AuthorizationRequest.authorizationCode({
      authorizationEndpoint: "not a url",
      clientId,
      redirectUri,
    }),
    {
      onFailure: (error) => error,
      onSuccess: () => null,
    },
  );

  const error = await Effect.runPromise(effect);

  expect(error).toBeInstanceOf(OAuth2AuthorizationRequest.ValidationError);
  expect(error?._tag).toBe("AuthorizationRequestValidationError");
  expect(error?.message).toBe("Invalid authorization endpoint");
});

it("rejects an empty client_id", async () => {
  const effect = Effect.match(
    OAuth2AuthorizationRequest.authorizationCode({
      authorizationEndpoint,
      clientId: "",
      redirectUri,
    }),
    {
      onFailure: (error) => error,
      onSuccess: () => null,
    },
  );

  const error = await Effect.runPromise(effect);

  expect(error).toBeInstanceOf(OAuth2AuthorizationRequest.ValidationError);
  expect(error?._tag).toBe("AuthorizationRequestValidationError");
  expect(error?.message).toBe("Invalid client id");
});

it("rejects an invalid redirect_uri", async () => {
  const effect = Effect.match(
    OAuth2AuthorizationRequest.authorizationCode({
      authorizationEndpoint,
      clientId,
      redirectUri: "not a url",
    }),
    {
      onFailure: (error) => error,
      onSuccess: () => null,
    },
  );

  const error = await Effect.runPromise(effect);

  expect(error).toBeInstanceOf(OAuth2AuthorizationRequest.ValidationError);
  expect(error?._tag).toBe("AuthorizationRequestValidationError");
  expect(error?.message).toBe("Invalid redirect uri");
});

it("rejects unsupported code challenge methods", async () => {
  const effect = Effect.match(
    OAuth2AuthorizationRequest.authorizationCode({
      authorizationEndpoint,
      clientId,
      codeChallenge: "challenge-123",
      codeChallengeMethod: "S512" as "S256",
      redirectUri,
    }),
    {
      onFailure: (error) => error,
      onSuccess: () => null,
    },
  );

  const error = await Effect.runPromise(effect);

  expect(error?._tag).toBe("CodeChallengeMethodError");
});

it("allows extension parameters when configured", async () => {
  const url = await Effect.runPromise(
    OAuth2AuthorizationRequest.authorizationCode({
      authorizationEndpoint,
      clientId,
      parameters: {
        audience: "https://api.example",
      },
      redirectUri,
    }),
  );

  expect(url.searchParams.get("audience")).toBe("https://api.example");
});

it("rejects extension parameters that collide with reserved OAuth parameters", async () => {
  const effect = Effect.match(
    OAuth2AuthorizationRequest.authorizationCode({
      authorizationEndpoint,
      clientId,
      parameters: {
        response_type: "token",
      },
      redirectUri,
    }),
    {
      onFailure: (error) => error,
      onSuccess: () => null,
    },
  );

  const error = await Effect.runPromise(effect);

  expect(error).toBeInstanceOf(OAuth2AuthorizationRequest.ValidationError);
  expect(error?._tag).toBe("AuthorizationRequestValidationError");
  expect(error?.message).toBe("Invalid authorization request parameter");
  expect(error).toMatchObject({ parameter: "response_type" });
});
