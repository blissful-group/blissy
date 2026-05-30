import { Effect } from "effect";
import { expect, it } from "vitest";

import { OAuth2ClientAuthentication } from "../client-authentication/client-authentication";
import { OAuth2TokenRevocationRequest } from "./token-revocation-request";

const revocationEndpoint = "https://authorization-server.example/revoke";

it("builds a token revocation request", async () => {
  const request = await Effect.runPromise(
    OAuth2TokenRevocationRequest.create({
      revocationEndpoint,
      token: "refresh-token-123",
      tokenTypeHint: "refresh_token",
    }),
  );

  expect(request.method).toBe("POST");
  expect(request.url).toBeInstanceOf(URL);
  expect(request.url.toString()).toBe(revocationEndpoint);
  expect(request.headers["Content-Type"]).toBe(
    "application/x-www-form-urlencoded",
  );
  expect(request.body.get("token")).toBe("refresh-token-123");
  expect(request.body.get("token_type_hint")).toBe("refresh_token");
});

it("supports client authentication", async () => {
  const authentication = await Effect.runPromise(
    OAuth2ClientAuthentication.clientSecretPost({
      clientId: "client-123",
      clientSecret: "secret-123",
    }),
  );
  const request = await Effect.runPromise(
    OAuth2TokenRevocationRequest.create({
      authentication,
      revocationEndpoint,
      token: "refresh-token-123",
    }),
  );

  expect(request.body.get("client_id")).toBe("client-123");
  expect(request.body.get("client_secret")).toBe("secret-123");
});

it("allows extension parameters", async () => {
  const request = await Effect.runPromise(
    OAuth2TokenRevocationRequest.create({
      parameters: {
        resource: "https://api.example",
        skipNull: null,
        skipUndefined: undefined,
      },
      revocationEndpoint,
      token: "refresh-token-123",
    }),
  );

  expect(request.body.get("resource")).toBe("https://api.example");
  expect(request.body.has("skipNull")).toBe(false);
  expect(request.body.has("skipUndefined")).toBe(false);
});
