import { Effect } from "effect";
import { expect, it } from "vitest";

import { OAuth2ScopeValidationError } from "./scope.errors";
import { Helper } from "./scope.helper";

it("deduplicates scopes", () => {
  expect(Helper.unique(["read", "write", "read"])).toEqual(["read", "write"]);
});

it("validates scopes", async () => {
  await expect(Effect.runPromise(Helper.validate("read"))).resolves.toBe(
    "read",
  );
});

it("rejects invalid scopes", async () => {
  const effect = Effect.match(Helper.validate("read write"), {
    onFailure: (error) => error,
    onSuccess: () => null,
  });

  const error = await Effect.runPromise(effect);

  expect(error).toBeInstanceOf(OAuth2ScopeValidationError);
  expect(error?._tag).toBe("OAuth2ScopeValidationError");
  expect(error?.message).toBe("Invalid OAuth2 scope");
});

it("validates all scopes", async () => {
  await Effect.runPromise(Helper.validateAll(["read", "write"]));
});
