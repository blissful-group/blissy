import { Effect, Schema } from "effect";

import { compare } from "../../utils/compare";
import { STATE_DEFAULT_BYTE_LENGTH } from "./state.constants";
import {
  OAuth2StateGenerationError,
  OAuth2StateValidationError,
} from "./state.errors";
import { StateByteLengthSchema } from "./state.schema";
import type { OAuth2StateValidationOptions } from "./state.types";

/**
 * Generates and validates OAuth 2.0 state values.
 */
export class OAuth2State {
  /**
   * Error returned when state generation input is invalid.
   */
  static GenerationError = OAuth2StateGenerationError;

  /**
   * Error returned when returned state does not match the expected state.
   */
  static ValidationError = OAuth2StateValidationError;

  /**
   * Generates a cryptographically random URL-safe state value.
   */
  static generate(byteLength = STATE_DEFAULT_BYTE_LENGTH) {
    return Effect.gen(function* () {
      yield* Effect.mapError(
        Schema.decodeUnknown(StateByteLengthSchema)(byteLength),
        () => {
          return new OAuth2StateGenerationError({
            byteLength,
            message: "Invalid OAuth2 state byte length",
          });
        },
      );

      const bytes = new Uint8Array(byteLength);
      globalThis.crypto.getRandomValues(bytes);

      return OAuth2State.encodeBase64Url(bytes);
    });
  }

  /**
   * Validates state returned from an authorization server callback.
   */
  static validate({
    expectedState,
    returnedState,
  }: OAuth2StateValidationOptions) {
    return Effect.gen(function* () {
      if (expectedState === undefined || expectedState === "") {
        const error = new OAuth2StateValidationError({
          message: "Missing OAuth2 state",
        });

        return yield* Effect.fail(error);
      }

      if (returnedState === undefined || returnedState === "") {
        const error = new OAuth2StateValidationError({
          message: "Missing OAuth2 state",
        });

        return yield* Effect.fail(error);
      }

      if (!compare.string(expectedState, returnedState)) {
        const error = new OAuth2StateValidationError({
          message: "Invalid OAuth2 state",
        });

        return yield* Effect.fail(error);
      }
    });
  }

  private static encodeBase64Url(bytes: Uint8Array) {
    let output = "";

    for (const byte of bytes) {
      output += String.fromCharCode(byte);
    }

    return btoa(output)
      .replaceAll("+", "-")
      .replaceAll("/", "_")
      .replaceAll("=", "");
  }
}

export namespace OAuth2State {
  export type ValidationOptions = OAuth2StateValidationOptions;
}
