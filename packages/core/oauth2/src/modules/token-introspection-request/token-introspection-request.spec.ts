import { Effect } from "effect";
import { expect, it } from "vitest";

import { OAuth2ClientAuthentication } from "../client-authentication/client-authentication";
import { OAuth2TokenIntrospectionRequest } from "./token-introspection-request";

const introspectionEndpoint = "https://authorization-server.example/introspect";

it("builds a token introspection request", async () => {
  const request = await Effect.runPromise(
    OAuth2TokenIntrospectionRequest.create({
      introspectionEndpoint,
      token: "access-token-123",
      tokenTypeHint: "access_token",
    }),
  );

  expect(request.method).toBe("POST");
  expect(request.url).toBeInstanceOf(URL);
  expect(request.url.toString()).toBe(introspectionEndpoint);
  expect(request.headers["Content-Type"]).toBe(
    "application/x-www-form-urlencoded",
  );
  expect(request.body.get("token")).toBe("access-token-123");
  expect(request.body.get("token_type_hint")).toBe("access_token");
});

it("supports client authentication", async () => {
  const authentication = await Effect.runPromise(
    OAuth2ClientAuthentication.clientSecretBasic({
      clientId: "client-123",
      clientSecret: "secret-123",
    }),
  );
  const request = await Effect.runPromise(
    OAuth2TokenIntrospectionRequest.create({
      authentication,
      introspectionEndpoint,
      token: "access-token-123",
    }),
  );

  expect(request.headers["Authorization"]).toBe(
    authentication.headers.Authorization,
  );
});

it("includes client authentication body parameters", async () => {
  const authentication = await Effect.runPromise(
    OAuth2ClientAuthentication.clientSecretPost({
      clientId: "client-123",
      clientSecret: "secret-123",
    }),
  );
  const request = await Effect.runPromise(
    OAuth2TokenIntrospectionRequest.create({
      authentication,
      introspectionEndpoint,
      token: "access-token-123",
    }),
  );

  expect(request.body.get("client_id")).toBe("client-123");
  expect(request.body.get("client_secret")).toBe("secret-123");
});

it("allows extension parameters", async () => {
  const request = await Effect.runPromise(
    OAuth2TokenIntrospectionRequest.create({
      introspectionEndpoint,
      parameters: {
        resource: "https://api.example",
        skipNull: null,
        skipUndefined: undefined,
      },
      token: "access-token-123",
    }),
  );

  expect(request.body.get("resource")).toBe("https://api.example");
  expect(request.body.has("skipNull")).toBe(false);
  expect(request.body.has("skipUndefined")).toBe(false);
});
