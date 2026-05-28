import { Effect } from "effect";
import { expect, it } from "vitest";

import { CryptoReference } from "./crypto";

const encoder = new TextEncoder();

it("provides default random values", async () => {
  const crypto = await Effect.runPromise(CryptoReference);
  const bytes = new Uint8Array(16);

  const result = crypto.randomValues(bytes);

  expect(result).toBe(bytes);
  expect(bytes.some((byte) => byte !== 0)).toBe(true);
});

it("provides default digest", async () => {
  const crypto = await Effect.runPromise(CryptoReference);
  const data = encoder.encode("hello world");

  const digest = await crypto.digest("SHA-256", data);

  expect(new Uint8Array(digest)).toEqual(
    new Uint8Array([
      185, 77, 39, 185, 147, 77, 62, 8, 165, 46, 82, 215, 218, 125, 171, 250,
      196, 132, 239, 227, 122, 83, 128, 238, 144, 136, 247, 172, 226, 239, 205,
      233,
    ]),
  );
});

it("provides default signing and verification", async () => {
  const crypto = await Effect.runPromise(CryptoReference);
  const key = await crypto.importKey(
    "raw",
    encoder.encode("super-secret-signing-key"),
    { hash: "SHA-256", name: "HMAC" },
    false,
    ["sign", "verify"],
  );
  const payload = encoder.encode("hello world");

  const signature = await crypto.sign("HMAC", key, payload);
  const valid = await crypto.verify("HMAC", key, signature, payload);

  expect(signature).toBeInstanceOf(ArrayBuffer);
  expect(valid).toBe(true);
});

it("provides default encryption and decryption", async () => {
  const crypto = await Effect.runPromise(CryptoReference);
  const key = await crypto.importKey(
    "raw",
    encoder.encode("0123456789abcdef0123456789abcdef"),
    { length: 256, name: "AES-GCM" },
    false,
    ["encrypt", "decrypt"],
  );
  const iv = new Uint8Array(12);
  const payload = encoder.encode("hello world");

  const ciphertext = await crypto.encrypt(
    { iv, name: "AES-GCM" },
    key,
    payload,
  );
  const decrypted = await crypto.decrypt(
    { iv, name: "AES-GCM" },
    key,
    ciphertext,
  );

  expect(new TextDecoder().decode(decrypted)).toBe("hello world");
});
