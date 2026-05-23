import { Effect } from "effect";
import { expect, it } from "vitest";

import { JWT } from "./jwt";

const encoder = new TextEncoder();
const key = encoder.encode("super-secret-signing-key");
const now = 1_700_000_000;

function createClaims(overrides: Partial<JWT.Claims> = {}): JWT.Claims {
  return {
    aud: "api",
    exp: now + 60,
    iat: now - 10,
    iss: "https://issuer.example",
    nbf: now - 10,
    sub: "user-123",
    ...overrides,
  };
}

it("signs a JWT", async () => {
  const token = await Effect.runPromise(
    JWT.sign({
      claims: createClaims(),
      key,
    }),
  );

  const segments = token.split(".");

  expect(segments).toHaveLength(3);
  expect(segments[0]).toBe("eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9");
  expect(segments[1]).toMatch(/^[A-Za-z0-9_-]+$/);
  expect(segments[2]).toMatch(/^[A-Za-z0-9_-]+$/);
});

it("verifies a JWT signature before trusting claims", async () => {
  const token = await Effect.runPromise(
    JWT.sign({
      claims: createClaims(),
      key,
    }),
  );

  const result = await Effect.runPromise(
    JWT.verify({
      audience: "api",
      issuer: "https://issuer.example",
      key,
      now,
      subject: "user-123",
      token,
    }),
  );

  expect(result.header).toEqual({ alg: "HS256", typ: "JWT" });
  expect(result.claims).toEqual(createClaims());
});

it("decodes a JWT without verification", async () => {
  const token = await Effect.runPromise(
    JWT.sign({
      claims: createClaims(),
      key,
    }),
  );

  const result = await Effect.runPromise(JWT.decode({ token }));

  expect(result.header).toEqual({ alg: "HS256", typ: "JWT" });
  expect(result.claims).toEqual(createClaims());
});

it("validates iss", async () => {
  const token = await Effect.runPromise(
    JWT.sign({
      claims: createClaims({ iss: "https://other.example" }),
      key,
    }),
  );
  const effect = Effect.match(
    JWT.verify({
      issuer: "https://issuer.example",
      key,
      now,
      token,
    }),
    {
      onFailure: (error) => error,
      onSuccess: () => null,
    },
  );

  const error = await Effect.runPromise(effect);

  expect(error).toBeInstanceOf(JWT.ClaimValidationError);
  expect(error?._tag).toBe("JWTClaimValidationError");
  expect(error?.message).toBe('Invalid JWT claim "iss"');
});

it("validates sub", async () => {
  const token = await Effect.runPromise(
    JWT.sign({
      claims: createClaims({ sub: "user-999" }),
      key,
    }),
  );
  const effect = Effect.match(
    JWT.verify({
      key,
      now,
      subject: "user-123",
      token,
    }),
    {
      onFailure: (error) => error,
      onSuccess: () => null,
    },
  );

  const error = await Effect.runPromise(effect);

  expect(error).toBeInstanceOf(JWT.ClaimValidationError);
  expect(error?._tag).toBe("JWTClaimValidationError");
  expect(error?.message).toBe('Invalid JWT claim "sub"');
});

it("validates aud", async () => {
  const token = await Effect.runPromise(
    JWT.sign({
      claims: createClaims({ aud: ["mobile", "web"] }),
      key,
    }),
  );
  const effect = Effect.match(
    JWT.verify({
      audience: "api",
      key,
      now,
      token,
    }),
    {
      onFailure: (error) => error,
      onSuccess: () => null,
    },
  );

  const error = await Effect.runPromise(effect);

  expect(error).toBeInstanceOf(JWT.ClaimValidationError);
  expect(error?._tag).toBe("JWTClaimValidationError");
  expect(error?.message).toBe('Invalid JWT claim "aud"');
});

it("validates exp", async () => {
  const token = await Effect.runPromise(
    JWT.sign({
      claims: createClaims({ exp: now - 1 }),
      key,
    }),
  );
  const effect = Effect.match(
    JWT.verify({
      key,
      now,
      token,
    }),
    {
      onFailure: (error) => error,
      onSuccess: () => null,
    },
  );

  const error = await Effect.runPromise(effect);

  expect(error).toBeInstanceOf(JWT.ClaimValidationError);
  expect(error?._tag).toBe("JWTClaimValidationError");
  expect(error?.message).toBe('Invalid JWT claim "exp"');
});

it("validates nbf", async () => {
  const token = await Effect.runPromise(
    JWT.sign({
      claims: createClaims({ nbf: now + 10 }),
      key,
    }),
  );
  const effect = Effect.match(
    JWT.verify({
      key,
      now,
      token,
    }),
    {
      onFailure: (error) => error,
      onSuccess: () => null,
    },
  );

  const error = await Effect.runPromise(effect);

  expect(error).toBeInstanceOf(JWT.ClaimValidationError);
  expect(error?._tag).toBe("JWTClaimValidationError");
  expect(error?.message).toBe('Invalid JWT claim "nbf"');
});

it("validates iat", async () => {
  const token = await Effect.runPromise(
    JWT.sign({
      claims: createClaims({ iat: now + 10 }),
      key,
    }),
  );
  const effect = Effect.match(
    JWT.verify({
      key,
      now,
      token,
    }),
    {
      onFailure: (error) => error,
      onSuccess: () => null,
    },
  );

  const error = await Effect.runPromise(effect);

  expect(error).toBeInstanceOf(JWT.ClaimValidationError);
  expect(error?._tag).toBe("JWTClaimValidationError");
  expect(error?.message).toBe('Invalid JWT claim "iat"');
});

it("allows configured clock tolerance", async () => {
  const token = await Effect.runPromise(
    JWT.sign({
      claims: createClaims({ exp: now - 1, iat: now + 1, nbf: now + 1 }),
      key,
    }),
  );

  const result = await Effect.runPromise(
    JWT.verify({
      clockTolerance: 1,
      key,
      now,
      token,
    }),
  );

  expect(result.claims).toEqual(
    createClaims({ exp: now - 1, iat: now + 1, nbf: now + 1 }),
  );
});

it("rejects expired tokens", async () => {
  const token = await Effect.runPromise(
    JWT.sign({
      claims: createClaims({ exp: now - 2 }),
      key,
    }),
  );
  const effect = Effect.match(
    JWT.verify({
      clockTolerance: 1,
      key,
      now,
      token,
    }),
    {
      onFailure: (error) => error,
      onSuccess: () => null,
    },
  );

  const error = await Effect.runPromise(effect);

  expect(error).toBeInstanceOf(JWT.ClaimValidationError);
  expect(error?._tag).toBe("JWTClaimValidationError");
  expect(error?.message).toBe('Invalid JWT claim "exp"');
});

it("rejects tokens used before nbf", async () => {
  const token = await Effect.runPromise(
    JWT.sign({
      claims: createClaims({ nbf: now + 2 }),
      key,
    }),
  );
  const effect = Effect.match(
    JWT.verify({
      clockTolerance: 1,
      key,
      now,
      token,
    }),
    {
      onFailure: (error) => error,
      onSuccess: () => null,
    },
  );

  const error = await Effect.runPromise(effect);

  expect(error).toBeInstanceOf(JWT.ClaimValidationError);
  expect(error?._tag).toBe("JWTClaimValidationError");
  expect(error?.message).toBe('Invalid JWT claim "nbf"');
});

it("rejects unsigned JWTs unless explicitly allowed", async () => {
  const token = `${btoa('{"alg":"none","typ":"JWT"}').replace(/\+/g, "-").replace(/\//g, "_").replace(/=+$/u, "")}.${btoa(JSON.stringify(createClaims())).replace(/\+/g, "-").replace(/\//g, "_").replace(/=+$/u, "")}.`;
  const effect = Effect.match(
    JWT.verify({
      now,
      token,
    }),
    {
      onFailure: (error) => error,
      onSuccess: () => null,
    },
  );

  const error = await Effect.runPromise(effect);

  expect(error).toBeInstanceOf(JWT.VerificationError);
  expect(error?._tag).toBe("JWTVerificationError");
  expect(error?.message).toBe("Unsigned JWTs are not allowed");
});

it("verifies unsigned JWTs when explicitly allowed", async () => {
  const token = `${btoa('{"alg":"none","typ":"JWT"}').replace(/\+/g, "-").replace(/\//g, "_").replace(/=+$/u, "")}.${btoa(JSON.stringify(createClaims())).replace(/\+/g, "-").replace(/\//g, "_").replace(/=+$/u, "")}.`;

  const result = await Effect.runPromise(
    JWT.verify({
      allowUnsecured: true,
      now,
      token,
    }),
  );

  expect(result.header).toEqual({ alg: "none", typ: "JWT" });
  expect(result.claims).toEqual(createClaims());
});

it("rejects JWTs with invalid signatures", async () => {
  const token = await Effect.runPromise(
    JWT.sign({
      claims: createClaims(),
      key,
    }),
  );
  const [headerSegment, payloadSegment, signatureSegment] = token.split(".");
  const invalidToken = [
    headerSegment,
    payloadSegment,
    `A${signatureSegment!.slice(1)}`,
  ].join(".");
  const effect = Effect.match(
    JWT.verify({
      key,
      now,
      token: invalidToken,
    }),
    {
      onFailure: (error) => error,
      onSuccess: () => null,
    },
  );

  const error = await Effect.runPromise(effect);

  expect(error).toBeInstanceOf(JWT.VerificationError);
  expect(error?._tag).toBe("JWTVerificationError");
  expect(error?.message).toBe("Invalid JWT signature");
});

it("rejects signed JWTs without a verification key", async () => {
  const token = await Effect.runPromise(
    JWT.sign({
      claims: createClaims(),
      key,
    }),
  );
  const effect = Effect.match(
    JWT.verify({
      now,
      token,
    }),
    {
      onFailure: (error) => error,
      onSuccess: () => null,
    },
  );

  const error = await Effect.runPromise(effect);

  expect(error).toBeInstanceOf(JWT.VerificationError);
  expect(error?._tag).toBe("JWTVerificationError");
  expect(error?.message).toBe("Invalid JWT signature");
});

it("rejects malformed JWT segment counts", async () => {
  const effect = Effect.match(JWT.decode({ token: "invalid-token" }), {
    onFailure: (error) => error,
    onSuccess: () => null,
  });

  const error = await Effect.runPromise(effect);

  expect(error).toBeInstanceOf(JWT.DecodeError);
  expect(error?._tag).toBe("JWTDecodeError");
  expect(error?.message).toBe("Invalid JWT");
});

it("rejects malformed JWT payloads", async () => {
  const token = "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.bm90LWpzb24.signature";
  const effect = Effect.match(JWT.decode({ token }), {
    onFailure: (error) => error,
    onSuccess: () => null,
  });

  const error = await Effect.runPromise(effect);

  expect(error).toBeInstanceOf(JWT.DecodeError);
  expect(error?._tag).toBe("JWTDecodeError");
  expect(error?.message).toBe("Invalid JWT");
});
