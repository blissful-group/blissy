import { CryptoReference } from "@blissy-auth/crypto/source";
import { Effect } from "effect";

import { STATE_DEFAULT_BYTE_LENGTH } from "./state.constants";
import {
  OAuth2StateGenerationError,
  OAuth2StateValidationError,
} from "./state.errors";
import { Helper } from "./state.helper";
import type { OAuth2StateValidationOptions } from "./state.types";

/**
 * Generates and validates OAuth 2.0 state values.
 */
export class OAuth2State {
  private static Helper = Helper;

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
      const crypto = yield* CryptoReference;

      yield* OAuth2State.Helper.validateByteLength(byteLength);

      const bytes = new Uint8Array(byteLength);
      crypto.randomValues(bytes);

      return OAuth2State.Helper.encodeBase64Url(bytes);
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
      yield* OAuth2State.Helper.validateExpectedState(expectedState);
      yield* OAuth2State.Helper.validateReturnedState(returnedState);
      yield* OAuth2State.Helper.validateStateMatch({
        expectedState: expectedState!,
        returnedState: returnedState!,
      });
    });
  }
}

export namespace OAuth2State {
  export type ValidationOptions = OAuth2StateValidationOptions;
}
