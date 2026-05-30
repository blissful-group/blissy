import { Effect } from "effect";
import { expect, it } from "vitest";

import { OAuth2TokenIntrospectionRequestValidationError } from "./token-introspection-request.errors";
import { Helper } from "./token-introspection-request.helper";

it("appends defined parameters", () => {
  const body = new URLSearchParams();

  Helper.append(body, { empty: undefined, token: "access-token-123" });

  expect(body.toString()).toBe("token=access-token-123");
});

it("parses introspection endpoint URLs", async () => {
  const url = await Effect.runPromise(
    Helper.parseUrl("https://authorization-server.example/introspect"),
  );

  expect(url.href).toBe("https://authorization-server.example/introspect");
});

it("rejects invalid introspection endpoint URLs", async () => {
  const effect = Effect.match(Helper.parseUrl("not a url"), {
    onFailure: (error) => error,
    onSuccess: () => null,
  });

  const error = await Effect.runPromise(effect);

  expect(error).toBeInstanceOf(OAuth2TokenIntrospectionRequestValidationError);
  expect(error?.message).toBe("Invalid introspection endpoint");
});

it("validates non-empty tokens", async () => {
  await expect(
    Effect.runPromise(Helper.validateNonEmpty("access-token-123")),
  ).resolves.toBe("access-token-123");
});

it("rejects empty tokens", async () => {
  const effect = Effect.match(Helper.validateNonEmpty(""), {
    onFailure: (error) => error,
    onSuccess: () => null,
  });

  const error = await Effect.runPromise(effect);

  expect(error).toBeInstanceOf(OAuth2TokenIntrospectionRequestValidationError);
  expect(error?.message).toBe("Invalid token");
});

it("validates token type hints", async () => {
  await expect(
    Effect.runPromise(Helper.validateTokenTypeHint("access_token")),
  ).resolves.toBe("access_token");
});

it("rejects invalid token type hints", async () => {
  const effect = Effect.match(
    Helper.validateTokenTypeHint("unsupported_token"),
    {
      onFailure: (error) => error,
      onSuccess: () => null,
    },
  );

  const error = await Effect.runPromise(effect);

  expect(error).toBeInstanceOf(OAuth2TokenIntrospectionRequestValidationError);
  expect(error?.message).toBe("Invalid token type hint");
});

it("rejects reserved extension parameters", async () => {
  const effect = Effect.match(Helper.validateExtensionParameter("token"), {
    onFailure: (error) => error,
    onSuccess: () => null,
  });

  const error = await Effect.runPromise(effect);

  expect(error).toBeInstanceOf(OAuth2TokenIntrospectionRequestValidationError);
  expect(error?.message).toBe("Invalid token introspection request parameter");
  expect(error).toMatchObject({ parameter: "token" });
});

it("allows non-reserved extension parameters", async () => {
  await Effect.runPromise(Helper.validateExtensionParameter("resource"));
});

it("detects reserved parameters", () => {
  expect(Helper.isReservedParameter("token_type_hint")).toBe(true);
  expect(Helper.isReservedParameter("resource")).toBe(false);
});
