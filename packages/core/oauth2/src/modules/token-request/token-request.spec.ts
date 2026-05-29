import { Effect } from "effect";
import { expect, it } from "vitest";

import { OAuth2ClientAuthentication } from "../client-authentication/client-authentication";
import { OAuth2TokenRequest } from "./token-request";

const tokenEndpoint = "https://authorization-server.example/token";

it("builds an authorization_code token request", async () => {
  const request = await Effect.runPromise(
    OAuth2TokenRequest.authorizationCode({
      code: "code-123",
      tokenEndpoint,
    }),
  );

  expect(request.method).toBe("POST");
  expect(request.url).toBeInstanceOf(URL);
  expect(request.url.toString()).toBe(tokenEndpoint);
  expect(request.body.get("grant_type")).toBe("authorization_code");
});

it("includes authorization code request parameters", async () => {
  const request = await Effect.runPromise(
    OAuth2TokenRequest.authorizationCode({
      code: "code-123",
      codeVerifier: "verifier-123",
      redirectUri: "https://client.example/callback",
      tokenEndpoint,
    }),
  );

  expect(request.body.get("code")).toBe("code-123");
  expect(request.body.get("redirect_uri")).toBe(
    "https://client.example/callback",
  );
  expect(request.body.get("code_verifier")).toBe("verifier-123");
});

it("builds a refresh_token token request", async () => {
  const request = await Effect.runPromise(
    OAuth2TokenRequest.refreshToken({
      refreshToken: "refresh-123",
      scope: ["read", "write", "read"],
      tokenEndpoint,
    }),
  );

  expect(request.body.get("grant_type")).toBe("refresh_token");
  expect(request.body.get("refresh_token")).toBe("refresh-123");
  expect(request.body.get("scope")).toBe("read write");
});

it("builds a client_credentials token request", async () => {
  const request = await Effect.runPromise(
    OAuth2TokenRequest.clientCredentials({
      scope: ["read"],
      tokenEndpoint,
    }),
  );

  expect(request.body.get("grant_type")).toBe("client_credentials");
  expect(request.body.get("scope")).toBe("read");
});

it("encodes request body as application/x-www-form-urlencoded", async () => {
  const request = await Effect.runPromise(
    OAuth2TokenRequest.authorizationCode({
      code: "code with spaces",
      tokenEndpoint,
    }),
  );

  expect(request.headers["Content-Type"]).toBe(
    "application/x-www-form-urlencoded",
  );
  expect(request.body.toString()).toContain("code=code+with+spaces");
});

it("supports client authentication", async () => {
  const authentication = await Effect.runPromise(
    OAuth2ClientAuthentication.clientSecretBasic({
      clientId: "client-123",
      clientSecret: "secret-123",
    }),
  );
  const request = await Effect.runPromise(
    OAuth2TokenRequest.authorizationCode({
      authentication,
      code: "code-123",
      tokenEndpoint,
    }),
  );

  expect(request.headers["Authorization"]).toBe(
    authentication.headers.Authorization,
  );
  expect(request.body.has("client_secret")).toBe(false);
});

it("includes client authentication body parameters", async () => {
  const authentication = await Effect.runPromise(
    OAuth2ClientAuthentication.clientSecretPost({
      clientId: "client-123",
      clientSecret: "secret-123",
    }),
  );
  const request = await Effect.runPromise(
    OAuth2TokenRequest.refreshToken({
      authentication,
      refreshToken: "refresh-123",
      tokenEndpoint,
    }),
  );

  expect(request.body.get("client_id")).toBe("client-123");
  expect(request.body.get("client_secret")).toBe("secret-123");
});

it("allows extension parameters", async () => {
  const request = await Effect.runPromise(
    OAuth2TokenRequest.clientCredentials({
      parameters: {
        audience: "https://api.example",
        ignoredNull: null,
        ignoredUndefined: undefined,
      },
      tokenEndpoint,
    }),
  );

  expect(request.body.get("audience")).toBe("https://api.example");
  expect(request.body.has("ignoredNull")).toBe(false);
  expect(request.body.has("ignoredUndefined")).toBe(false);
});

it("omits undefined optional parameters", async () => {
  const request = await Effect.runPromise(
    OAuth2TokenRequest.authorizationCode({
      code: "code-123",
      tokenEndpoint,
    }),
  );

  expect(request.body.has("redirect_uri")).toBe(false);
  expect(request.body.has("code_verifier")).toBe(false);
});

it("rejects invalid redirect_uri", async () => {
  const effect = Effect.match(
    OAuth2TokenRequest.authorizationCode({
      code: "code-123",
      redirectUri: "not a url",
      tokenEndpoint,
    }),
    {
      onFailure: (error) => error,
      onSuccess: () => null,
    },
  );

  const error = await Effect.runPromise(effect);

  expect(error).toBeInstanceOf(OAuth2TokenRequest.ValidationError);
  expect(error?.message).toBe("Invalid token endpoint");
});

it("rejects invalid scope values", async () => {
  const effect = Effect.match(
    OAuth2TokenRequest.clientCredentials({
      scope: ["invalid\\scope"],
      tokenEndpoint,
    }),
    {
      onFailure: (error) => error,
      onSuccess: () => null,
    },
  );

  const error = await Effect.runPromise(effect);

  expect(error?._tag).toBe("OAuth2ScopeValidationError");
});

it("rejects extension parameters that collide with reserved token request parameters", async () => {
  const effect = Effect.match(
    OAuth2TokenRequest.clientCredentials({
      parameters: {
        grant_type: "password",
      },
      tokenEndpoint,
    }),
    {
      onFailure: (error) => error,
      onSuccess: () => null,
    },
  );

  const error = await Effect.runPromise(effect);

  expect(error).toBeInstanceOf(OAuth2TokenRequest.ValidationError);
  expect(error?.message).toBe("Invalid token request parameter");
  expect(error).toMatchObject({ parameter: "grant_type" });
});

it("does not include authorization headers in public error messages", async () => {
  const authorization = "Basic super-secret-header";
  const effect = Effect.match(
    OAuth2TokenRequest.clientCredentials({
      authentication: {
        bodyParameters: {},
        headers: {
          Authorization: authorization,
        },
      },
      parameters: {
        grant_type: "password",
      },
      tokenEndpoint,
    }),
    {
      onFailure: (error) => error,
      onSuccess: () => null,
    },
  );

  const error = await Effect.runPromise(effect);

  expect(JSON.stringify(error)).not.toContain(authorization);
});
