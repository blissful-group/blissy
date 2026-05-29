import { Effect } from "effect";
import { expect, it } from "vitest";

import { AuthorizationRequestValidationError } from "./authorization-request.errors";
import { Helper } from "./authorization-request.helper";

it("parses authorization URLs", async () => {
  const url = await Effect.runPromise(
    Helper.parseUrl(
      "https://auth.example/authorize",
      "Invalid authorization endpoint",
    ),
  );

  expect(url.href).toBe("https://auth.example/authorize");
});

it("rejects invalid authorization URLs", async () => {
  const effect = Effect.match(
    Helper.parseUrl("not a url", "Invalid authorization endpoint"),
    {
      onFailure: (error) => error,
      onSuccess: () => null,
    },
  );

  const error = await Effect.runPromise(effect);

  expect(error).toBeInstanceOf(AuthorizationRequestValidationError);
  expect(error?.message).toBe("Invalid authorization endpoint");
});

it("validates non-empty values", async () => {
  await expect(
    Effect.runPromise(Helper.validateNonEmpty("client", "Invalid client id")),
  ).resolves.toBe("client");
});

it("rejects empty values", async () => {
  const effect = Effect.match(
    Helper.validateNonEmpty("", "Invalid client id"),
    {
      onFailure: (error) => error,
      onSuccess: () => null,
    },
  );

  const error = await Effect.runPromise(effect);

  expect(error).toBeInstanceOf(AuthorizationRequestValidationError);
  expect(error?.message).toBe("Invalid client id");
});

it("rejects reserved extension parameters", async () => {
  const effect = Effect.match(Helper.validateExtensionParameter("client_id"), {
    onFailure: (error) => error,
    onSuccess: () => null,
  });

  const error = await Effect.runPromise(effect);

  expect(error).toBeInstanceOf(AuthorizationRequestValidationError);
  expect(error?._tag).toBe("AuthorizationRequestValidationError");
  expect(error?.message).toBe("Invalid authorization request parameter");
});

it("allows non-reserved extension parameters", async () => {
  await Effect.runPromise(Helper.validateExtensionParameter("prompt"));
});

it("detects reserved parameters", () => {
  expect(Helper.isReservedParameter("client_id")).toBe(true);
  expect(Helper.isReservedParameter("prompt")).toBe(false);
});
