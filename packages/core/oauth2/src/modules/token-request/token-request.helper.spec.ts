import { Effect } from "effect";
import { expect, it } from "vitest";

import { OAuth2TokenRequestValidationError } from "./token-request.errors";
import { Helper } from "./token-request.helper";

it("appends defined parameters", () => {
  const body = new URLSearchParams();

  Helper.append(body, { empty: undefined, grant_type: "client_credentials" });

  expect(body.toString()).toBe("grant_type=client_credentials");
});

it("parses token endpoint URLs", async () => {
  const url = await Effect.runPromise(
    Helper.parseUrl("https://server.example/token", "Invalid token endpoint"),
  );

  expect(url.href).toBe("https://server.example/token");
});

it("rejects invalid token endpoint URLs", async () => {
  const effect = Effect.match(
    Helper.parseUrl("not a url", "Invalid token endpoint"),
    {
      onFailure: (error) => error,
      onSuccess: () => null,
    },
  );

  const error = await Effect.runPromise(effect);

  expect(error).toBeInstanceOf(OAuth2TokenRequestValidationError);
  expect(error?.message).toBe("Invalid token endpoint");
});

it("validates non-empty token request values", async () => {
  await expect(
    Effect.runPromise(
      Helper.validateNonEmpty("code", "Invalid authorization code"),
    ),
  ).resolves.toBe("code");
});

it("rejects empty token request values", async () => {
  const effect = Effect.match(
    Helper.validateNonEmpty("", "Invalid authorization code"),
    {
      onFailure: (error) => error,
      onSuccess: () => null,
    },
  );

  const error = await Effect.runPromise(effect);

  expect(error).toBeInstanceOf(OAuth2TokenRequestValidationError);
  expect(error?.message).toBe("Invalid authorization code");
});

it("rejects reserved extension parameters", async () => {
  const effect = Effect.match(Helper.validateExtensionParameter("grant_type"), {
    onFailure: (error) => error,
    onSuccess: () => null,
  });

  const error = await Effect.runPromise(effect);

  expect(error).toBeInstanceOf(OAuth2TokenRequestValidationError);
  expect(error?._tag).toBe("OAuth2TokenRequestValidationError");
  expect(error?.message).toBe("Invalid token request parameter");
});

it("allows non-reserved extension parameters", async () => {
  await Effect.runPromise(Helper.validateExtensionParameter("resource"));
});

it("detects reserved parameters", () => {
  expect(Helper.isReservedParameter("grant_type")).toBe(true);
  expect(Helper.isReservedParameter("resource")).toBe(false);
});
