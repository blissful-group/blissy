import { Effect, Schema } from "effect";

import { compare } from "../../utils/compare";
import {
  OAuth2StateGenerationError,
  OAuth2StateValidationError,
} from "./state.errors";
import { StateByteLengthSchema } from "./state.schema";

export class Helper {
  static validateByteLength(byteLength: number) {
    return Effect.mapError(
      Schema.decodeUnknown(StateByteLengthSchema)(byteLength),
      () =>
        new OAuth2StateGenerationError({
          byteLength,
          message: "Invalid OAuth2 state byte length",
        }),
    );
  }

  static validateExpectedState(expectedState?: string) {
    if (expectedState !== undefined && expectedState !== "") return Effect.void;

    return Effect.fail(
      new OAuth2StateValidationError({ message: "Missing OAuth2 state" }),
    );
  }

  static validateReturnedState(returnedState?: string) {
    if (returnedState !== undefined && returnedState !== "") return Effect.void;

    return Effect.fail(
      new OAuth2StateValidationError({ message: "Missing OAuth2 state" }),
    );
  }

  static validateStateMatch({
    expectedState,
    returnedState,
  }: {
    expectedState: string;
    returnedState: string;
  }) {
    if (compare.string(expectedState, returnedState)) return Effect.void;

    return Effect.fail(
      new OAuth2StateValidationError({ message: "Invalid OAuth2 state" }),
    );
  }

  static encodeBase64Url(bytes: Uint8Array) {
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
