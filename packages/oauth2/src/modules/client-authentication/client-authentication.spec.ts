import { Effect } from "effect";
import { expect, it } from "vitest";

import { OAuth2ClientAuthentication } from "./client-authentication";

it("supports public client authentication with no secret", async () => {
  const authentication = await Effect.runPromise(
    OAuth2ClientAuthentication.none({ clientId: "client-123" }),
  );

  expect(authentication).toEqual({
    bodyParameters: {},
    headers: {},
  });
});

it("includes client_id in the request body for public clients when required", async () => {
  const authentication = await Effect.runPromise(
    OAuth2ClientAuthentication.none({
      clientId: "client-123",
      includeClientId: true,
    }),
  );

  expect(authentication).toEqual({
    bodyParameters: {
      client_id: "client-123",
    },
    headers: {},
  });
});

it("does not set an Authorization header for public clients", async () => {
  const authentication = await Effect.runPromise(
    OAuth2ClientAuthentication.none({
      clientId: "client-123",
      includeClientId: true,
    }),
  );

  expect(authentication.headers).not.toHaveProperty("Authorization");
});

it("rejects client_secret when authentication method is none if strict", async () => {
  const effect = Effect.match(
    OAuth2ClientAuthentication.none({
      clientId: "client-123",
      clientSecret: "secret-123",
      strict: true,
    }),
    {
      onFailure: (error) => error,
      onSuccess: () => null,
    },
  );

  const error = await Effect.runPromise(effect);

  expect(error).toBeInstanceOf(OAuth2ClientAuthentication.Error);
  expect(error?._tag).toBe("OAuth2ClientAuthenticationError");
  expect(error?.message).toBe("Invalid OAuth2 client authentication");
});

it("sets an HTTP Basic Authorization header", async () => {
  const authentication = await Effect.runPromise(
    OAuth2ClientAuthentication.clientSecretBasic({
      clientId: "client-123",
      clientSecret: "secret-123",
    }),
  );

  expect(authentication.headers.Authorization).toBe(
    `Basic ${btoa("client-123:secret-123")}`,
  );
});

it("base64-encodes client_id and client_secret", async () => {
  const authentication = await Effect.runPromise(
    OAuth2ClientAuthentication.clientSecretBasic({
      clientId: "client-123",
      clientSecret: "secret-123",
    }),
  );

  expect(authentication.headers.Authorization).toBe(
    "Basic Y2xpZW50LTEyMzpzZWNyZXQtMTIz",
  );
});

it("URL-encodes client_id and client_secret before Basic encoding", async () => {
  const authentication = await Effect.runPromise(
    OAuth2ClientAuthentication.clientSecretBasic({
      clientId: "client id",
      clientSecret: "secret:with space",
    }),
  );

  expect(authentication.headers.Authorization).toBe(
    `Basic ${btoa("client+id:secret%3Awith+space")}`,
  );
});

it("does not include client_secret in the request body for client_secret_basic", async () => {
  const authentication = await Effect.runPromise(
    OAuth2ClientAuthentication.clientSecretBasic({
      clientId: "client-123",
      clientSecret: "secret-123",
    }),
  );

  expect(authentication.bodyParameters).not.toHaveProperty("client_secret");
});

it("rejects missing client_id for client_secret_basic", async () => {
  const effect = Effect.match(
    OAuth2ClientAuthentication.clientSecretBasic({
      clientId: "",
      clientSecret: "secret-123",
    }),
    {
      onFailure: (error) => error,
      onSuccess: () => null,
    },
  );

  const error = await Effect.runPromise(effect);

  expect(error).toBeInstanceOf(OAuth2ClientAuthentication.Error);
  expect(error?._tag).toBe("OAuth2ClientAuthenticationError");
  expect(error?.message).toBe("Invalid OAuth2 client id");
});

it("rejects empty client_secret for client_secret_basic", async () => {
  const effect = Effect.match(
    OAuth2ClientAuthentication.clientSecretBasic({
      clientId: "client-123",
      clientSecret: "",
    }),
    {
      onFailure: (error) => error,
      onSuccess: () => null,
    },
  );

  const error = await Effect.runPromise(effect);

  expect(error).toBeInstanceOf(OAuth2ClientAuthentication.Error);
  expect(error?._tag).toBe("OAuth2ClientAuthenticationError");
  expect(error?.message).toBe("Invalid OAuth2 client secret");
});

it("handles special characters in client_id", async () => {
  const authentication = await Effect.runPromise(
    OAuth2ClientAuthentication.clientSecretBasic({
      clientId: "client:id",
      clientSecret: "secret-123",
    }),
  );

  expect(authentication.headers.Authorization).toBe(
    `Basic ${btoa("client%3Aid:secret-123")}`,
  );
});

it("handles special characters in client_secret", async () => {
  const authentication = await Effect.runPromise(
    OAuth2ClientAuthentication.clientSecretBasic({
      clientId: "client-123",
      clientSecret: "secret:with/symbols",
    }),
  );

  expect(authentication.headers.Authorization).toBe(
    `Basic ${btoa("client-123:secret%3Awith%2Fsymbols")}`,
  );
});

it("places client_id in the request body for client_secret_post", async () => {
  const authentication = await Effect.runPromise(
    OAuth2ClientAuthentication.clientSecretPost({
      clientId: "client-123",
      clientSecret: "secret-123",
    }),
  );

  expect(authentication.bodyParameters.client_id).toBe("client-123");
});

it("places client_secret in the request body for client_secret_post", async () => {
  const authentication = await Effect.runPromise(
    OAuth2ClientAuthentication.clientSecretPost({
      clientId: "client-123",
      clientSecret: "secret-123",
    }),
  );

  expect(authentication.bodyParameters.client_secret).toBe("secret-123");
});

it("does not set an Authorization header for client_secret_post", async () => {
  const authentication = await Effect.runPromise(
    OAuth2ClientAuthentication.clientSecretPost({
      clientId: "client-123",
      clientSecret: "secret-123",
    }),
  );

  expect(authentication.headers).not.toHaveProperty("Authorization");
});

it("rejects missing client_id for client_secret_post", async () => {
  const effect = Effect.match(
    OAuth2ClientAuthentication.clientSecretPost({
      clientId: "",
      clientSecret: "secret-123",
    }),
    {
      onFailure: (error) => error,
      onSuccess: () => null,
    },
  );

  const error = await Effect.runPromise(effect);

  expect(error).toBeInstanceOf(OAuth2ClientAuthentication.Error);
  expect(error?._tag).toBe("OAuth2ClientAuthenticationError");
  expect(error?.message).toBe("Invalid OAuth2 client id");
});

it("rejects empty client_secret for client_secret_post", async () => {
  const effect = Effect.match(
    OAuth2ClientAuthentication.clientSecretPost({
      clientId: "client-123",
      clientSecret: "",
    }),
    {
      onFailure: (error) => error,
      onSuccess: () => null,
    },
  );

  const error = await Effect.runPromise(effect);

  expect(error).toBeInstanceOf(OAuth2ClientAuthentication.Error);
  expect(error?._tag).toBe("OAuth2ClientAuthenticationError");
  expect(error?.message).toBe("Invalid OAuth2 client secret");
});

it("URL-encodes client_secret in the form body when serialized", async () => {
  const authentication = await Effect.runPromise(
    OAuth2ClientAuthentication.clientSecretPost({
      clientId: "client-123",
      clientSecret: "secret with spaces",
    }),
  );
  const body = new URLSearchParams(authentication.bodyParameters).toString();

  expect(body).toContain("client_secret=secret+with+spaces");
});
