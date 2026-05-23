import { Effect } from "effect";
import { expect, it } from "vitest";

import { JWS } from "./jws";
import { JWSCriticalHeaderError, JWSVerificationError } from "./jws.errors";

const encoder = new TextEncoder();
const decoder = new TextDecoder();
const key = encoder.encode("super-secret-signing-key");
const payload = encoder.encode("hello world");

it("creates compact JWS serialization", async () => {
  const token = await Effect.runPromise(
    JWS.signCompact({
      key,
      payload,
      protectedHeader: {
        alg: "HS256",
        typ: "JWT",
      },
    }),
  );

  const segments = token.split(".");

  expect(segments).toHaveLength(3);
  expect(segments[0]).toBe("eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9");
  expect(segments[1]).toBe("aGVsbG8gd29ybGQ");
  expect(segments[2]).toMatch(/^[A-Za-z0-9_-]+$/);
});

it("verifies compact JWS serialization", async () => {
  const token = await Effect.runPromise(
    JWS.signCompact({
      key,
      payload,
      protectedHeader: {
        alg: "HS256",
        typ: "JWT",
      },
    }),
  );

  const result = await Effect.runPromise(JWS.verifyCompact({ key, token }));

  expect(decoder.decode(result.payload)).toBe("hello world");
  expect(result.protectedHeader).toEqual({
    alg: "HS256",
    typ: "JWT",
  });
});

it("verifies known critical headers", async () => {
  const token = await Effect.runPromise(
    JWS.signCompact({
      key,
      payload,
      protectedHeader: {
        alg: "HS256",
        crit: ["typ"],
        typ: "JWT",
      },
    }),
  );

  const result = await Effect.runPromise(JWS.verifyCompact({ key, token }));

  expect(decoder.decode(result.payload)).toBe("hello world");
  expect(result.protectedHeader).toEqual({
    alg: "HS256",
    crit: ["typ"],
    typ: "JWT",
  });
});

it("creates flattened JSON JWS serialization", async () => {
  const serialization = await Effect.runPromise(
    JWS.signFlattened({
      key,
      payload,
      protectedHeader: {
        alg: "HS256",
      },
      header: {
        kid: "key-1",
      },
    }),
  );

  expect(serialization).toEqual({
    payload: "aGVsbG8gd29ybGQ",
    protected: "eyJhbGciOiJIUzI1NiJ9",
    header: {
      kid: "key-1",
    },
    signature: expect.stringMatching(/^[A-Za-z0-9_-]+$/),
  });
});

it("creates general JSON JWS serialization", async () => {
  const serialization = await Effect.runPromise(
    JWS.signGeneral({
      payload,
      signatures: [
        {
          key,
          protectedHeader: {
            alg: "HS256",
          },
          header: {
            kid: "key-1",
          },
        },
        {
          key: encoder.encode("another-secret-signing-key"),
          protectedHeader: {
            alg: "HS256",
          },
          header: {
            kid: "key-2",
          },
        },
      ],
    }),
  );

  expect(serialization.payload).toBe("aGVsbG8gd29ybGQ");
  expect(serialization.signatures).toHaveLength(2);
  expect(serialization.signatures[0]).toEqual({
    protected: "eyJhbGciOiJIUzI1NiJ9",
    header: {
      kid: "key-1",
    },
    signature: expect.stringMatching(/^[A-Za-z0-9_-]+$/),
  });
  expect(serialization.signatures[1]).toEqual({
    protected: "eyJhbGciOiJIUzI1NiJ9",
    header: {
      kid: "key-2",
    },
    signature: expect.stringMatching(/^[A-Za-z0-9_-]+$/),
  });
});

it("rejects tampered payloads", async () => {
  const token = await Effect.runPromise(
    JWS.signCompact({
      key,
      payload,
      protectedHeader: {
        alg: "HS256",
      },
    }),
  );
  const tamperedToken = token.replace("aGVsbG8gd29ybGQ", "aGVsbG8gd29ybGQh");
  const effect = Effect.match(
    JWS.verifyCompact({ key, token: tamperedToken }),
    {
      onFailure: (error) => error,
      onSuccess: () => null,
    },
  );

  const error = await Effect.runPromise(effect);

  expect(error).toBeInstanceOf(JWSVerificationError);
  expect(error?._tag).toBe("JWSVerificationError");
  expect(error?.message).toBe("Invalid JWS signature");
});

it("rejects tampered protected headers", async () => {
  const token = await Effect.runPromise(
    JWS.signCompact({
      key,
      payload,
      protectedHeader: {
        alg: "HS256",
      },
    }),
  );
  const [protectedSegment, payloadSegment, signatureSegment] = token.split(".");
  const tamperedToken = [
    "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9",
    payloadSegment,
    signatureSegment,
  ].join(".");
  const effect = Effect.match(
    JWS.verifyCompact({ key, token: tamperedToken }),
    {
      onFailure: (error) => error,
      onSuccess: () => null,
    },
  );

  const error = await Effect.runPromise(effect);

  expect(protectedSegment).toBe("eyJhbGciOiJIUzI1NiJ9");
  expect(error).toBeInstanceOf(JWSVerificationError);
  expect(error?._tag).toBe("JWSVerificationError");
  expect(error?.message).toBe("Invalid JWS signature");
});

it("rejects invalid signatures", async () => {
  const token = await Effect.runPromise(
    JWS.signCompact({
      key,
      payload,
      protectedHeader: {
        alg: "HS256",
      },
    }),
  );
  const [protectedSegment, payloadSegment, signatureSegment] = token.split(".");
  const invalidSignature = `A${signatureSegment!.slice(1)}`;
  const invalidToken = [
    protectedSegment,
    payloadSegment,
    invalidSignature,
  ].join(".");
  const effect = Effect.match(JWS.verifyCompact({ key, token: invalidToken }), {
    onFailure: (error) => error,
    onSuccess: () => null,
  });

  const error = await Effect.runPromise(effect);

  expect(error).toBeInstanceOf(JWSVerificationError);
  expect(error?._tag).toBe("JWSVerificationError");
  expect(error?.message).toBe("Invalid JWS signature");
});

it("rejects unknown critical headers", async () => {
  const token = await Effect.runPromise(
    JWS.signCompact({
      key,
      payload,
      protectedHeader: {
        alg: "HS256",
        crit: ["exp"],
        exp: "required",
      },
    }),
  );
  const effect = Effect.match(JWS.verifyCompact({ key, token }), {
    onFailure: (error) => error,
    onSuccess: () => null,
  });

  const error = await Effect.runPromise(effect);

  expect(error).toBeInstanceOf(JWSCriticalHeaderError);
  expect(error?._tag).toBe("JWSCriticalHeaderError");
  expect(error?.message).toBe('Unknown critical header parameter: "exp"');
});

it("rejects malformed compact serializations", async () => {
  const effect = Effect.match(
    JWS.verifyCompact({ key, token: "invalid-token" }),
    {
      onFailure: (error) => error,
      onSuccess: () => null,
    },
  );

  const error = await Effect.runPromise(effect);

  expect(error).toBeInstanceOf(JWSVerificationError);
  expect(error?._tag).toBe("JWSVerificationError");
  expect(error?.message).toBe("Invalid compact JWS serialization");
});
