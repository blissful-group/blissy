import { Effect } from "effect";
import { expect, it } from "vitest";

import { OAuth2State } from "./state";

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

it("validates matching state values", async () => {
  await expect(
    Effect.runPromise(
      OAuth2State.validate({
        expectedState: "state-123",
        returnedState: "state-123",
      }),
    ),
  ).resolves.toBeUndefined();
});

it("validates matching percent-encodable state values", async () => {
  await expect(
    Effect.runPromise(
      OAuth2State.validate({
        expectedState: "state with spaces",
        returnedState: "state with spaces",
      }),
    ),
  ).resolves.toBeUndefined();
});

it("rejects missing expected state", async () => {
  const effect = Effect.match(
    OAuth2State.validate({ returnedState: "state-123" }),
    {
      onFailure: (error) => error,
      onSuccess: () => null,
    },
  );

  const error = await Effect.runPromise(effect);

  expect(error).toBeInstanceOf(OAuth2State.ValidationError);
  expect(error?._tag).toBe("OAuth2StateValidationError");
  expect(error?.message).toBe("Missing OAuth2 state");
});

it("rejects missing returned state", async () => {
  const effect = Effect.match(
    OAuth2State.validate({ expectedState: "state-123" }),
    {
      onFailure: (error) => error,
      onSuccess: () => null,
    },
  );

  const error = await Effect.runPromise(effect);

  expect(error).toBeInstanceOf(OAuth2State.ValidationError);
  expect(error?._tag).toBe("OAuth2StateValidationError");
  expect(error?.message).toBe("Missing OAuth2 state");
});

it("rejects mismatched state values", async () => {
  const effect = Effect.match(
    OAuth2State.validate({
      expectedState: "state-123",
      returnedState: "state-456",
    }),
    {
      onFailure: (error) => error,
      onSuccess: () => null,
    },
  );

  const error = await Effect.runPromise(effect);

  expect(error).toBeInstanceOf(OAuth2State.ValidationError);
  expect(error?._tag).toBe("OAuth2StateValidationError");
  expect(error?.message).toBe("Invalid OAuth2 state");
});

it("rejects empty expected state", async () => {
  const effect = Effect.match(
    OAuth2State.validate({
      expectedState: "",
      returnedState: "state-123",
    }),
    {
      onFailure: (error) => error,
      onSuccess: () => null,
    },
  );

  const error = await Effect.runPromise(effect);

  expect(error).toBeInstanceOf(OAuth2State.ValidationError);
  expect(error?._tag).toBe("OAuth2StateValidationError");
  expect(error?.message).toBe("Missing OAuth2 state");
});

it("rejects empty returned state", async () => {
  const effect = Effect.match(
    OAuth2State.validate({
      expectedState: "state-123",
      returnedState: "",
    }),
    {
      onFailure: (error) => error,
      onSuccess: () => null,
    },
  );

  const error = await Effect.runPromise(effect);

  expect(error).toBeInstanceOf(OAuth2State.ValidationError);
  expect(error?._tag).toBe("OAuth2StateValidationError");
  expect(error?.message).toBe("Missing OAuth2 state");
});
