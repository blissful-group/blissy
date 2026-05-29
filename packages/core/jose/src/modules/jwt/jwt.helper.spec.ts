import { Effect } from "effect";
import { expect, it } from "vitest";

import { JWTClaimValidationError } from "./jwt.errors";
import { Helper } from "./jwt.helper";

const now = 1_700_000_000;

it("validates iss", async () => {
  const effect = Effect.match(
    Helper.validateIssuer({
      claims: { iss: "https://other.example" },
      issuer: "https://issuer.example",
    }),
    {
      onFailure: (error) => error,
      onSuccess: () => null,
    },
  );

  const error = await Effect.runPromise(effect);

  expect(error).toBeInstanceOf(JWTClaimValidationError);
  expect(error?._tag).toBe("JWTClaimValidationError");
  expect(error?.message).toBe('Invalid JWT claim "iss"');
});

it("validates sub", async () => {
  const effect = Effect.match(
    Helper.validateSubject({
      claims: { sub: "user-999" },
      subject: "user-123",
    }),
    {
      onFailure: (error) => error,
      onSuccess: () => null,
    },
  );

  const error = await Effect.runPromise(effect);

  expect(error).toBeInstanceOf(JWTClaimValidationError);
  expect(error?._tag).toBe("JWTClaimValidationError");
  expect(error?.message).toBe('Invalid JWT claim "sub"');
});

it("validates aud", async () => {
  const effect = Effect.match(
    Helper.validateAudience({
      audience: "api",
      claims: { aud: ["mobile", "web"] },
    }),
    {
      onFailure: (error) => error,
      onSuccess: () => null,
    },
  );

  const error = await Effect.runPromise(effect);

  expect(error).toBeInstanceOf(JWTClaimValidationError);
  expect(error?._tag).toBe("JWTClaimValidationError");
  expect(error?.message).toBe('Invalid JWT claim "aud"');
});

it("allows aud arrays containing the expected audience", async () => {
  await Effect.runPromise(
    Helper.validateAudience({
      audience: "api",
      claims: { aud: ["mobile", "api"] },
    }),
  );
});

it("validates exp", async () => {
  const effect = Effect.match(
    Helper.validateExpiration({
      claims: { exp: now - 1 },
      clockTolerance: 0,
      now,
    }),
    {
      onFailure: (error) => error,
      onSuccess: () => null,
    },
  );

  const error = await Effect.runPromise(effect);

  expect(error).toBeInstanceOf(JWTClaimValidationError);
  expect(error?._tag).toBe("JWTClaimValidationError");
  expect(error?.message).toBe('Invalid JWT claim "exp"');
});

it("allows missing exp", async () => {
  await Effect.runPromise(
    Helper.validateExpiration({
      claims: {},
      clockTolerance: 0,
      now,
    }),
  );
});

it("allows exp within clock tolerance", async () => {
  await Effect.runPromise(
    Helper.validateExpiration({
      claims: { exp: now - 1 },
      clockTolerance: 1,
      now,
    }),
  );
});

it("rejects exp outside clock tolerance", async () => {
  const effect = Effect.match(
    Helper.validateExpiration({
      claims: { exp: now - 2 },
      clockTolerance: 1,
      now,
    }),
    {
      onFailure: (error) => error,
      onSuccess: () => null,
    },
  );

  const error = await Effect.runPromise(effect);

  expect(error).toBeInstanceOf(JWTClaimValidationError);
  expect(error?._tag).toBe("JWTClaimValidationError");
  expect(error?.message).toBe('Invalid JWT claim "exp"');
});

it("validates nbf", async () => {
  const effect = Effect.match(
    Helper.validateNotBefore({
      claims: { nbf: now + 1 },
      clockTolerance: 0,
      now,
    }),
    {
      onFailure: (error) => error,
      onSuccess: () => null,
    },
  );

  const error = await Effect.runPromise(effect);

  expect(error).toBeInstanceOf(JWTClaimValidationError);
  expect(error?._tag).toBe("JWTClaimValidationError");
  expect(error?.message).toBe('Invalid JWT claim "nbf"');
});

it("allows missing nbf", async () => {
  await Effect.runPromise(
    Helper.validateNotBefore({
      claims: {},
      clockTolerance: 0,
      now,
    }),
  );
});

it("allows nbf within clock tolerance", async () => {
  await Effect.runPromise(
    Helper.validateNotBefore({
      claims: { nbf: now + 1 },
      clockTolerance: 1,
      now,
    }),
  );
});

it("rejects nbf outside clock tolerance", async () => {
  const effect = Effect.match(
    Helper.validateNotBefore({
      claims: { nbf: now + 2 },
      clockTolerance: 1,
      now,
    }),
    {
      onFailure: (error) => error,
      onSuccess: () => null,
    },
  );

  const error = await Effect.runPromise(effect);

  expect(error).toBeInstanceOf(JWTClaimValidationError);
  expect(error?._tag).toBe("JWTClaimValidationError");
  expect(error?.message).toBe('Invalid JWT claim "nbf"');
});

it("validates iat", async () => {
  const effect = Effect.match(
    Helper.validateIssuedAt({
      claims: { iat: now + 1 },
      clockTolerance: 0,
      now,
    }),
    {
      onFailure: (error) => error,
      onSuccess: () => null,
    },
  );

  const error = await Effect.runPromise(effect);

  expect(error).toBeInstanceOf(JWTClaimValidationError);
  expect(error?._tag).toBe("JWTClaimValidationError");
  expect(error?.message).toBe('Invalid JWT claim "iat"');
});

it("allows missing iat", async () => {
  await Effect.runPromise(
    Helper.validateIssuedAt({
      claims: {},
      clockTolerance: 0,
      now,
    }),
  );
});

it("allows iat within clock tolerance", async () => {
  await Effect.runPromise(
    Helper.validateIssuedAt({
      claims: { iat: now + 1 },
      clockTolerance: 1,
      now,
    }),
  );
});
