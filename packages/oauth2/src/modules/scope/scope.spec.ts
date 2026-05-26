import { Effect } from "effect";
import { expect, it } from "vitest";

import { OAuth2Scope } from "./scope";

it("parses an empty scope string as an empty scope set", async () => {
  const scopes = await Effect.runPromise(OAuth2Scope.parse(""));

  expect(scopes).toEqual([]);
});

it("parses a single scope value", async () => {
  const scopes = await Effect.runPromise(OAuth2Scope.parse("openid"));

  expect(scopes).toEqual(["openid"]);
});

it("parses multiple space-delimited scope values", async () => {
  const scopes = await Effect.runPromise(
    OAuth2Scope.parse("openid profile email"),
  );

  expect(scopes).toEqual(["openid", "profile", "email"]);
});

it("trims surrounding whitespace when parsing scopes", async () => {
  const scopes = await Effect.runPromise(OAuth2Scope.parse("  openid  "));

  expect(scopes).toEqual(["openid"]);
});

it("normalizes repeated internal whitespace when parsing scopes", async () => {
  const scopes = await Effect.runPromise(
    OAuth2Scope.parse("openid   profile\nemail\tphone"),
  );

  expect(scopes).toEqual(["openid", "profile", "email", "phone"]);
});

it("rejects scope values containing invalid characters", async () => {
  const invalidScopeEffect = Effect.match(
    OAuth2Scope.format(['profile"read']),
    {
      onFailure: (error) => error,
      onSuccess: () => null,
    },
  );

  const invalidScopeError = await Effect.runPromise(invalidScopeEffect);

  expect(invalidScopeError).toBeInstanceOf(OAuth2Scope.ValidationError);
  expect(invalidScopeError?._tag).toBe("OAuth2ScopeValidationError");
  expect(invalidScopeError?.message).toBe("Invalid OAuth2 scope");
  expect(invalidScopeError?.scope).toBe('profile"read');
});

it("normalizes duplicate scope values when parsing scopes", async () => {
  const scopes = await Effect.runPromise(
    OAuth2Scope.parse("openid profile openid"),
  );

  expect(scopes).toEqual(["openid", "profile"]);
});

it("normalizes duplicate scope values when formatting scopes", async () => {
  const scope = await Effect.runPromise(
    OAuth2Scope.format(["openid", "profile", "openid"]),
  );

  expect(scope).toBe("openid profile");
});

it("formats an empty scope set as an empty string", async () => {
  const scope = await Effect.runPromise(OAuth2Scope.format([]));

  expect(scope).toBe("");
});

it("formats a single scope value", async () => {
  const scope = await Effect.runPromise(OAuth2Scope.format(["openid"]));

  expect(scope).toBe("openid");
});

it("formats multiple scope values using spaces", async () => {
  const scope = await Effect.runPromise(
    OAuth2Scope.format(["openid", "profile", "email"]),
  );

  expect(scope).toBe("openid profile email");
});

it("round-trips valid parsed scopes through formatting", async () => {
  const parsed = await Effect.runPromise(
    OAuth2Scope.parse("openid profile email"),
  );
  const formatted = await Effect.runPromise(OAuth2Scope.format(parsed));

  expect(formatted).toBe("openid profile email");
});

it("checks whether a scope set includes a required scope", async () => {
  const includesScope = await Effect.runPromise(
    OAuth2Scope.includes(["openid", "profile"], "openid"),
  );
  const excludesScope = await Effect.runPromise(
    OAuth2Scope.includes(["openid", "profile"], "email"),
  );

  expect(includesScope).toBe(true);
  expect(excludesScope).toBe(false);
});

it("checks whether a scope set includes all required scopes", async () => {
  const includesAll = await Effect.runPromise(
    OAuth2Scope.includesAll(
      ["openid", "profile", "email", "email"],
      ["openid", "profile", "profile"],
    ),
  );
  const excludesSome = await Effect.runPromise(
    OAuth2Scope.includesAll(["openid", "profile"], ["openid", "email"]),
  );

  expect(includesAll).toBe(true);
  expect(excludesSome).toBe(false);
});

it("checks whether a scope set includes any allowed scope", async () => {
  const includesAny = await Effect.runPromise(
    OAuth2Scope.includesAny(
      ["openid", "profile", "profile"],
      ["email", "profile", "profile"],
    ),
  );
  const excludesAll = await Effect.runPromise(
    OAuth2Scope.includesAny(["openid", "profile"], ["email", "phone"]),
  );

  expect(includesAny).toBe(true);
  expect(excludesAll).toBe(false);
});

it("computes missing scopes from a required scope set", async () => {
  const missingScopes = await Effect.runPromise(
    OAuth2Scope.missing(
      ["openid", "profile", "profile"],
      ["openid", "profile", "email", "email"],
    ),
  );

  expect(missingScopes).toEqual(["email"]);
});
