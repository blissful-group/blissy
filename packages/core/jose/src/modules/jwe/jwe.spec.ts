import { CryptoReference } from "@blissy-auth/crypto/source";
import { Effect } from "effect";
import { expect, it } from "vitest";

import { JWE } from "./jwe";

const encoder = new TextEncoder();
const decoder = new TextDecoder();
const key = encoder.encode("0123456789abcdef0123456789abcdef");
const payload = encoder.encode("hello world");
const cryptoService = CryptoReference.defaultValue();

it("creates compact JWE serialization", async () => {
  const token = await Effect.runPromise(
    JWE.encryptCompact({
      key,
      payload,
      protectedHeader: {
        alg: "dir",
        enc: "A256GCM",
      },
    }),
  );

  const segments = token.split(".");

  expect(segments).toHaveLength(5);
  expect(segments[0]).toBe("eyJhbGciOiJkaXIiLCJlbmMiOiJBMjU2R0NNIn0");
  expect(segments[1]).toBe("");
  expect(segments[2]).toMatch(/^[A-Za-z0-9_-]+$/);
  expect(segments[3]).toMatch(/^[A-Za-z0-9_-]+$/);
  expect(segments[4]).toMatch(/^[A-Za-z0-9_-]+$/);
});

it("supports dependency injection for initialization vectors", async () => {
  const service = Effect.provideService(CryptoReference, {
    ...cryptoService,
    randomValues(bytes) {
      bytes.fill(0);

      return bytes;
    },
  });
  const token = await Effect.runPromise(
    JWE.encryptCompact({
      key,
      payload,
      protectedHeader: {
        alg: "dir",
        enc: "A256GCM",
      },
    }).pipe(service),
  );

  expect(token.split(".")[2]).toBe("AAAAAAAAAAAAAAAA");
});

it("decrypts compact JWE serialization", async () => {
  const token = await Effect.runPromise(
    JWE.encryptCompact({
      key,
      payload,
      protectedHeader: {
        alg: "dir",
        enc: "A256GCM",
      },
    }),
  );

  const result = await Effect.runPromise(JWE.decryptCompact({ key, token }));

  expect(decoder.decode(result.payload)).toBe("hello world");
  expect(result.protectedHeader).toEqual({
    alg: "dir",
    enc: "A256GCM",
  });
});

it("creates flattened JSON JWE serialization", async () => {
  const serialization = await Effect.runPromise(
    JWE.encryptFlattened({
      key,
      payload,
      protectedHeader: {
        alg: "dir",
        enc: "A256GCM",
      },
      header: {
        kid: "key-1",
      },
    }),
  );

  expect(serialization).toEqual({
    ciphertext: expect.stringMatching(/^[A-Za-z0-9_-]+$/),
    encrypted_key: "",
    header: {
      kid: "key-1",
    },
    iv: expect.stringMatching(/^[A-Za-z0-9_-]+$/),
    protected: "eyJhbGciOiJkaXIiLCJlbmMiOiJBMjU2R0NNIn0",
    tag: expect.stringMatching(/^[A-Za-z0-9_-]+$/),
  });
});

it("creates general JSON JWE serialization", async () => {
  const serialization = await Effect.runPromise(
    JWE.encryptGeneral({
      key,
      payload,
      protectedHeader: {
        alg: "dir",
        enc: "A256GCM",
      },
      recipients: [{ header: { kid: "key-1" } }, { header: { kid: "key-2" } }],
    }),
  );

  expect(serialization).toEqual({
    ciphertext: expect.stringMatching(/^[A-Za-z0-9_-]+$/),
    iv: expect.stringMatching(/^[A-Za-z0-9_-]+$/),
    protected: "eyJhbGciOiJkaXIiLCJlbmMiOiJBMjU2R0NNIn0",
    recipients: [
      {
        encrypted_key: "",
        header: {
          kid: "key-1",
        },
      },
      {
        encrypted_key: "",
        header: {
          kid: "key-2",
        },
      },
    ],
    tag: expect.stringMatching(/^[A-Za-z0-9_-]+$/),
  });
});

it("decrypts the matching recipient in general JSON serialization", async () => {
  const serialization = await Effect.runPromise(
    JWE.encryptGeneral({
      key,
      payload,
      protectedHeader: {
        alg: "dir",
        enc: "A256GCM",
      },
      recipients: [{ header: { kid: "key-1" } }, { header: { kid: "key-2" } }],
    }),
  );

  const result = await Effect.runPromise(
    JWE.decryptGeneral({
      key,
      serialization,
      kid: "key-2",
    }),
  );

  expect(decoder.decode(result.payload)).toBe("hello world");
  expect(result.protectedHeader).toEqual({
    alg: "dir",
    enc: "A256GCM",
  });
  expect(result.recipient).toEqual({
    encrypted_key: "",
    header: {
      kid: "key-2",
    },
  });
});

it("rejects invalid authentication tags", async () => {
  const token = await Effect.runPromise(
    JWE.encryptCompact({
      key,
      payload,
      protectedHeader: {
        alg: "dir",
        enc: "A256GCM",
      },
    }),
  );
  const [
    protectedSegment,
    encryptedKeySegment,
    ivSegment,
    ciphertextSegment,
    tagSegment,
  ] = token.split(".");
  const invalidToken = [
    protectedSegment,
    encryptedKeySegment,
    ivSegment,
    ciphertextSegment,
    `A${tagSegment!.slice(1)}`,
  ].join(".");
  const effect = Effect.match(
    JWE.decryptCompact({ key, token: invalidToken }),
    {
      onFailure: (error) => error,
      onSuccess: () => null,
    },
  );

  const error = await Effect.runPromise(effect);

  expect(error).toBeInstanceOf(JWE.DecryptionError);
  expect(error?._tag).toBe("JWEDecryptionError");
  expect(error?.message).toBe("Invalid JWE ciphertext");
});

it("rejects tampered protected headers", async () => {
  const token = await Effect.runPromise(
    JWE.encryptCompact({
      key,
      payload,
      protectedHeader: {
        alg: "dir",
        enc: "A256GCM",
      },
    }),
  );
  const [, encryptedKeySegment, ivSegment, ciphertextSegment, tagSegment] =
    token.split(".");
  const tamperedToken = [
    "eyJhbGciOiJkaXIiLCJlbmMiOiJBMjU2R0NNIiwidHlwIjoiSldUIn0",
    encryptedKeySegment,
    ivSegment,
    ciphertextSegment,
    tagSegment,
  ].join(".");
  const effect = Effect.match(
    JWE.decryptCompact({ key, token: tamperedToken }),
    {
      onFailure: (error) => error,
      onSuccess: () => null,
    },
  );

  const error = await Effect.runPromise(effect);

  expect(error).toBeInstanceOf(JWE.DecryptionError);
  expect(error?._tag).toBe("JWEDecryptionError");
  expect(error?.message).toBe("Invalid JWE ciphertext");
});

it("rejects malformed compact JWE serializations", async () => {
  const effect = Effect.match(
    JWE.decryptCompact({ key, token: "invalid-token" }),
    {
      onFailure: (error) => error,
      onSuccess: () => null,
    },
  );

  const error = await Effect.runPromise(effect);

  expect(error).toBeInstanceOf(JWE.DecryptionError);
  expect(error?._tag).toBe("JWEDecryptionError");
  expect(error?.message).toBe("Invalid JWE ciphertext");
});

it("rejects non-empty encrypted key segments for dir", async () => {
  const token = await Effect.runPromise(
    JWE.encryptCompact({
      key,
      payload,
      protectedHeader: {
        alg: "dir",
        enc: "A256GCM",
      },
    }),
  );
  const [, , ivSegment, ciphertextSegment, tagSegment] = token.split(".");
  const invalidToken = [
    "eyJhbGciOiJkaXIiLCJlbmMiOiJBMjU2R0NNIn0",
    "Zm9v",
    ivSegment,
    ciphertextSegment,
    tagSegment,
  ].join(".");
  const effect = Effect.match(
    JWE.decryptCompact({ key, token: invalidToken }),
    {
      onFailure: (error) => error,
      onSuccess: () => null,
    },
  );

  const error = await Effect.runPromise(effect);

  expect(error).toBeInstanceOf(JWE.DecryptionError);
  expect(error?._tag).toBe("JWEDecryptionError");
  expect(error?.message).toBe("Invalid JWE ciphertext");
});
