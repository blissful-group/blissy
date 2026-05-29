import { Effect } from "effect";
import { expect, it } from "vitest";

import {
  OAuth2StateGenerationError,
  OAuth2StateValidationError,
} from "./state.errors";
import { Helper } from "./state.helper";

it("base64url-encodes state bytes", () => {
  expect(Helper.encodeBase64Url(new Uint8Array([251, 255]))).toBe("-_8");
});

it("validates state byte length", async () => {
  await expect(Effect.runPromise(Helper.validateByteLength(32))).resolves.toBe(
    32,
  );
});

it("rejects invalid state byte length", async () => {
  const effect = Effect.match(Helper.validateByteLength(0), {
    onFailure: (error) => error,
    onSuccess: () => null,
  });

  const error = await Effect.runPromise(effect);

  expect(error).toBeInstanceOf(OAuth2StateGenerationError);
  expect(error?.message).toBe("Invalid OAuth2 state byte length");
});

it("validates expected state", async () => {
  await Effect.runPromise(Helper.validateExpectedState("state"));
});

it("rejects missing expected state", async () => {
  const effect = Effect.match(Helper.validateExpectedState(""), {
    onFailure: (error) => error,
    onSuccess: () => null,
  });

  const error = await Effect.runPromise(effect);

  expect(error).toBeInstanceOf(OAuth2StateValidationError);
  expect(error?.message).toBe("Missing OAuth2 state");
});

it("validates returned state", async () => {
  await Effect.runPromise(Helper.validateReturnedState("state"));
});

it("rejects missing returned state", async () => {
  const effect = Effect.match(Helper.validateReturnedState(""), {
    onFailure: (error) => error,
    onSuccess: () => null,
  });

  const error = await Effect.runPromise(effect);

  expect(error).toBeInstanceOf(OAuth2StateValidationError);
  expect(error?.message).toBe("Missing OAuth2 state");
});

it("validates matching state", async () => {
  await Effect.runPromise(
    Helper.validateStateMatch({
      expectedState: "state",
      returnedState: "state",
    }),
  );
});

it("rejects mismatched state", async () => {
  const effect = Effect.match(
    Helper.validateStateMatch({
      expectedState: "expected",
      returnedState: "actual",
    }),
    {
      onFailure: (error) => error,
      onSuccess: () => null,
    },
  );

  const error = await Effect.runPromise(effect);

  expect(error).toBeInstanceOf(OAuth2StateValidationError);
  expect(error?._tag).toBe("OAuth2StateValidationError");
  expect(error?.message).toBe("Invalid OAuth2 state");
});
