import { Effect } from "effect";
import { expect, it } from "vitest";

import { JWAAlgorithmNotSupportedError } from "./jwa.errors";
import { Helper } from "./jwa.helper";

it("allows supported algorithms", async () => {
  await Effect.runPromise(Helper.validateAlgorithm("HS256"));
  await Effect.runPromise(Helper.validateAlgorithm("RS256"));
  await Effect.runPromise(Helper.validateAlgorithm("ES256"));
});

it("rejects unsupported algorithms", async () => {
  const effect = Effect.match(Helper.validateAlgorithm("PS256"), {
    onFailure: (error) => error,
    onSuccess: () => null,
  });

  const error = await Effect.runPromise(effect);

  expect(error).toBeInstanceOf(JWAAlgorithmNotSupportedError);
  expect(error?._tag).toBe("JWAAlgorithmNotSupportedError");
  expect(error?.message).toBe('Unsupported JWA algorithm: "PS256"');
});
