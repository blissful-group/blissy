import { Effect } from "effect";
import { bench, describe } from "vitest";

import { Base64 } from "./base64";

const createBytes = (length: number) =>
  Uint8Array.from({ length }, (_, index) => index % 256);

const smallBytes = createBytes(32);
const mediumBytes = createBytes(4_096);
const largeBytes = createBytes(65_536);

const smallEncoded = Effect.runSync(Base64.encode(smallBytes));
const mediumEncoded = Effect.runSync(Base64.encode(mediumBytes));
const largeEncoded = Effect.runSync(Base64.encode(largeBytes));

describe("Base64", () => {
  bench("encodes a small payload", () => {
    Effect.runSync(Base64.encode(smallBytes));
  });

  bench("encodes a medium payload", () => {
    Effect.runSync(Base64.encode(mediumBytes));
  });

  bench("encodes a large payload", () => {
    Effect.runSync(Base64.encode(largeBytes));
  });

  bench("decodes a small payload", () => {
    Effect.runSync(Base64.decode(smallEncoded));
  });

  bench("decodes a medium payload", () => {
    Effect.runSync(Base64.decode(mediumEncoded));
  });

  bench("decodes a large payload", () => {
    Effect.runSync(Base64.decode(largeEncoded));
  });
});
