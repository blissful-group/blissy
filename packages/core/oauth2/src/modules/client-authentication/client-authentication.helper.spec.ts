import { Effect } from "effect";
import { expect, it } from "vitest";

import { OAuth2ClientAuthenticationError } from "./client-authentication.errors";
import { Helper } from "./client-authentication.helper";

it("form-encodes credentials", () => {
  expect(Helper.formEncode("client:id")).toBe("client%3Aid");
});

it("validates client ids", async () => {
  await expect(
    Effect.runPromise(Helper.validateClientId("client")),
  ).resolves.toBe("client");
});

it("rejects invalid client ids", async () => {
  const effect = Effect.match(Helper.validateClientId(""), {
    onFailure: (error) => error,
    onSuccess: () => null,
  });

  const error = await Effect.runPromise(effect);

  expect(error).toBeInstanceOf(OAuth2ClientAuthenticationError);
  expect(error?._tag).toBe("OAuth2ClientAuthenticationError");
  expect(error?.message).toBe("Invalid OAuth2 client id");
});

it("validates client secrets", async () => {
  await expect(
    Effect.runPromise(Helper.validateClientSecret("secret")),
  ).resolves.toBe("secret");
});

it("rejects invalid client secrets", async () => {
  const effect = Effect.match(Helper.validateClientSecret(""), {
    onFailure: (error) => error,
    onSuccess: () => null,
  });

  const error = await Effect.runPromise(effect);

  expect(error).toBeInstanceOf(OAuth2ClientAuthenticationError);
  expect(error?._tag).toBe("OAuth2ClientAuthenticationError");
  expect(error?.message).toBe("Invalid OAuth2 client secret");
});
