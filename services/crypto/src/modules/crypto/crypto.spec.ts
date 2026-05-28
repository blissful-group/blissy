import { Effect } from "effect";
import { expect, it } from "vitest";

import { CryptoReference } from "./crypto";

it("provides default random values", async () => {
  const crypto = await Effect.runPromise(CryptoReference);
  const bytes = new Uint8Array(16);

  const result = crypto.randomValues(bytes);

  expect(result).toBe(bytes);
  expect(bytes.some((byte) => byte !== 0)).toBe(true);
});

it("provides default digest", async () => {
  const crypto = await Effect.runPromise(CryptoReference);
  const data = new TextEncoder().encode("hello world");

  const digest = await crypto.digest("SHA-256", data);

  expect(new Uint8Array(digest)).toEqual(
    new Uint8Array([
      185, 77, 39, 185, 147, 77, 62, 8, 165, 46, 82, 215, 218, 125, 171, 250,
      196, 132, 239, 227, 122, 83, 128, 238, 144, 136, 247, 172, 226, 239, 205,
      233,
    ]),
  );
});
