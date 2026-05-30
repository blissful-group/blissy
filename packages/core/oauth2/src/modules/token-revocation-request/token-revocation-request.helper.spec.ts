import { Effect } from "effect";
import { expect, it } from "vitest";

import { OAuth2TokenRevocationRequestValidationError } from "./token-revocation-request.errors";
import { Helper } from "./token-revocation-request.helper";

it("appends defined parameters", () => {
  const body = new URLSearchParams();

  Helper.append(body, { empty: undefined, token: "refresh-token-123" });

  expect(body.toString()).toBe("token=refresh-token-123");
});

it("parses revocation endpoint URLs", async () => {
  const url = await Effect.runPromise(
    Helper.parseUrl("https://authorization-server.example/revoke"),
  );

  expect(url.href).toBe("https://authorization-server.example/revoke");
});

it("rejects invalid revocation endpoint URLs", async () => {
  const effect = Effect.match(Helper.parseUrl("not a url"), {
    onFailure: (error) => error,
    onSuccess: () => null,
  });

  const error = await Effect.runPromise(effect);

  expect(error).toBeInstanceOf(OAuth2TokenRevocationRequestValidationError);
  expect(error?.message).toBe("Invalid revocation endpoint");
});

it("validates non-empty tokens", async () => {
  await expect(
    Effect.runPromise(Helper.validateNonEmpty("refresh-token-123")),
  ).resolves.toBe("refresh-token-123");
});

it("rejects empty tokens", async () => {
  const effect = Effect.match(Helper.validateNonEmpty(""), {
    onFailure: (error) => error,
    onSuccess: () => null,
  });

  const error = await Effect.runPromise(effect);

  expect(error).toBeInstanceOf(OAuth2TokenRevocationRequestValidationError);
  expect(error?.message).toBe("Invalid token");
});

it("validates token type hints", async () => {
  await expect(
    Effect.runPromise(Helper.validateTokenTypeHint("refresh_token")),
  ).resolves.toBe("refresh_token");
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

  expect(error).toBeInstanceOf(OAuth2TokenRevocationRequestValidationError);
  expect(error?.message).toBe("Invalid token type hint");
});

it("rejects reserved extension parameters", async () => {
  const effect = Effect.match(
    Helper.validateExtensionParameter("token_type_hint"),
    {
      onFailure: (error) => error,
      onSuccess: () => null,
    },
  );

  const error = await Effect.runPromise(effect);

  expect(error).toBeInstanceOf(OAuth2TokenRevocationRequestValidationError);
  expect(error?.message).toBe("Invalid token revocation request parameter");
  expect(error).toMatchObject({ parameter: "token_type_hint" });
});

it("allows non-reserved extension parameters", async () => {
  await Effect.runPromise(Helper.validateExtensionParameter("resource"));
});

it("detects reserved parameters", () => {
  expect(Helper.isReservedParameter("token")).toBe(true);
  expect(Helper.isReservedParameter("resource")).toBe(false);
});
