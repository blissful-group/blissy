import { CryptoReference } from "@blissy-auth/crypto";
import { Effect } from "effect";
import { expect, it } from "vitest";

import { OAuth2State } from "./state";

const cryptoService = CryptoReference.defaultValue();

it("generates a non-empty state value", async () => {
  const state = await Effect.runPromise(OAuth2State.generate());

  expect(state).not.toBe("");
});

it("generates URL-safe state values", async () => {
  const state = await Effect.runPromise(OAuth2State.generate());

  expect(state).toMatch(/^[A-Za-z0-9_-]+$/u);
  expect(state).not.toContain("=");
});

it("generates different state values across calls", async () => {
  const firstState = await Effect.runPromise(OAuth2State.generate());
  const secondState = await Effect.runPromise(OAuth2State.generate());

  expect(firstState).not.toBe(secondState);
});

it("supports configurable state byte length", async () => {
  const state = await Effect.runPromise(OAuth2State.generate(16));

  expect(state).toHaveLength(22);
});

it("supports dependency injection for randomness", async () => {
  const service = Effect.provideService(CryptoReference, {
    ...cryptoService,
    randomValues: (bytes) => {
      bytes.set([0xff, 0xee, 0xdd, 0xcc]);

      return bytes;
    },
  });
  const effect = OAuth2State.generate(4).pipe(service);
  const state = await Effect.runPromise(effect);

  expect(state).toBe("_-7dzA");
});

it("rejects state generation with zero length", async () => {
  const effect = Effect.match(OAuth2State.generate(0), {
    onFailure: (error) => error,
    onSuccess: () => null,
  });

  const error = await Effect.runPromise(effect);

  expect(error).toBeInstanceOf(OAuth2State.GenerationError);
  expect(error?._tag).toBe("OAuth2StateGenerationError");
  expect(error?.message).toBe("Invalid OAuth2 state byte length");
  expect(error).toMatchObject({ byteLength: 0 });
});

it("rejects state generation with negative length", async () => {
  const effect = Effect.match(OAuth2State.generate(-1), {
    onFailure: (error) => error,
    onSuccess: () => null,
  });

  const error = await Effect.runPromise(effect);

  expect(error).toBeInstanceOf(OAuth2State.GenerationError);
  expect(error?._tag).toBe("OAuth2StateGenerationError");
  expect(error?.message).toBe("Invalid OAuth2 state byte length");
  expect(error).toMatchObject({ byteLength: -1 });
});

it("rejects state generation with fractional length", async () => {
  const effect = Effect.match(OAuth2State.generate(1.5), {
    onFailure: (error) => error,
    onSuccess: () => null,
  });

  const error = await Effect.runPromise(effect);

  expect(error).toBeInstanceOf(OAuth2State.GenerationError);
  expect(error?._tag).toBe("OAuth2StateGenerationError");
  expect(error?.message).toBe("Invalid OAuth2 state byte length");
  expect(error).toMatchObject({ byteLength: 1.5 });
});
