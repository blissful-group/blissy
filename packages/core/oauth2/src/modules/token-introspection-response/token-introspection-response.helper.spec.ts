import { Effect } from "effect";
import { expect, it } from "vitest";

import { OAuth2TokenIntrospectionResponseValidationError } from "./token-introspection-response.errors";
import { Helper } from "./token-introspection-response.helper";

it("parses object records", async () => {
  const record = await Effect.runPromise(Helper.parseRecord({ active: false }));

  expect(record).toEqual({ active: false });
});

it("rejects non-object responses", async () => {
  const effect = Effect.match(Helper.parseRecord(null), {
    onFailure: (error) => error,
    onSuccess: () => null,
  });

  const error = await Effect.runPromise(effect);

  expect(error).toBeInstanceOf(OAuth2TokenIntrospectionResponseValidationError);
  expect(error?.message).toBe("Invalid token introspection response");
});

it("parses active flags", async () => {
  await expect(Effect.runPromise(Helper.parseActive(true))).resolves.toBe(true);
});

it("rejects invalid active flags", async () => {
  const effect = Effect.match(Helper.parseActive(undefined), {
    onFailure: (error) => error,
    onSuccess: () => null,
  });

  const error = await Effect.runPromise(effect);

  expect(error).toBeInstanceOf(OAuth2TokenIntrospectionResponseValidationError);
  expect(error?.message).toBe("Invalid active flag");
});

it("parses scope claims", async () => {
  const scope = await Effect.runPromise(Helper.parseScope("read write read"));

  expect(scope).toEqual(["read", "write"]);
});

it("rejects invalid scope claims", async () => {
  const effect = Effect.match(Helper.parseScope("invalid\\scope"), {
    onFailure: (error) => error,
    onSuccess: () => null,
  });

  const error = await Effect.runPromise(effect);

  expect(error).toBeInstanceOf(OAuth2TokenIntrospectionResponseValidationError);
  expect(error?.message).toBe("Invalid token scope");
  expect(error).toMatchObject({ claim: "scope" });
});

it("parses token type claims", async () => {
  await expect(
    Effect.runPromise(Helper.parseTokenType("Bearer")),
  ).resolves.toBe("Bearer");
});

it("rejects invalid token type claims", async () => {
  const effect = Effect.match(Helper.parseTokenType(""), {
    onFailure: (error) => error,
    onSuccess: () => null,
  });

  const error = await Effect.runPromise(effect);

  expect(error).toBeInstanceOf(OAuth2TokenIntrospectionResponseValidationError);
  expect(error?.message).toBe("Invalid token type");
  expect(error).toMatchObject({ claim: "token_type" });
});

it("parses string claims", async () => {
  await expect(
    Effect.runPromise(Helper.parseStringClaim("client-123", "client_id")),
  ).resolves.toBe("client-123");
});

it("rejects invalid string claims", async () => {
  const effect = Effect.match(Helper.parseStringClaim("", "client_id"), {
    onFailure: (error) => error,
    onSuccess: () => null,
  });

  const error = await Effect.runPromise(effect);

  expect(error).toBeInstanceOf(OAuth2TokenIntrospectionResponseValidationError);
  expect(error?.message).toBe("Invalid token introspection string claim");
  expect(error).toMatchObject({ claim: "client_id" });
});

it("parses string list claims", async () => {
  await expect(
    Effect.runPromise(Helper.parseStringListClaim(["api-1"], "aud")),
  ).resolves.toEqual(["api-1"]);
});

it("rejects invalid string list claims", async () => {
  const effect = Effect.match(
    Helper.parseStringListClaim(["api-1", 123], "aud"),
    {
      onFailure: (error) => error,
      onSuccess: () => null,
    },
  );

  const error = await Effect.runPromise(effect);

  expect(error).toBeInstanceOf(OAuth2TokenIntrospectionResponseValidationError);
  expect(error?.message).toBe("Invalid token introspection string list claim");
  expect(error).toMatchObject({ claim: "aud" });
});

it("parses timestamp claims", async () => {
  await expect(
    Effect.runPromise(Helper.parseTimestampClaim(1_706_000_000, "exp")),
  ).resolves.toBe(1_706_000_000);
});

it("rejects invalid timestamp claims", async () => {
  const effect = Effect.match(Helper.parseTimestampClaim(-1, "exp"), {
    onFailure: (error) => error,
    onSuccess: () => null,
  });

  const error = await Effect.runPromise(effect);

  expect(error).toBeInstanceOf(OAuth2TokenIntrospectionResponseValidationError);
  expect(error?.message).toBe("Invalid token introspection timestamp claim");
  expect(error).toMatchObject({ claim: "exp" });
});
