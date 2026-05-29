import { CryptoReference } from "@blissy-auth/crypto/source";
import { Effect } from "effect";

import { NONCE_DEFAULT_BYTE_LENGTH } from "./nonce.constants";
import {
  OIDCNonceGenerationError,
  OIDCNonceValidationError,
} from "./nonce.errors";
import { Helper } from "./nonce.helper";

/**
 * Generates and validates OpenID Connect nonce values.
 */
export class OIDCNonce {
  private static Helper = Helper;

  /**
   * Error returned when nonce generation input is invalid.
   */
  static GenerationError = OIDCNonceGenerationError;

  /**
   * Error returned when returned nonce does not match the expected nonce.
   */
  static ValidationError = OIDCNonceValidationError;

  /**
   * Generates a cryptographically random URL-safe nonce value.
   */
  static generate(byteLength = NONCE_DEFAULT_BYTE_LENGTH) {
    return Effect.gen(function* () {
      const crypto = yield* CryptoReference;

      yield* OIDCNonce.Helper.validateByteLength(byteLength);

      const bytes = new Uint8Array(byteLength);
      crypto.randomValues(bytes);

      return OIDCNonce.Helper.encodeBase64Url(bytes);
    });
  }

  /**
   * Validates a nonce returned in an ID token.
   */
  static validate({
    expectedNonce,
    returnedNonce,
  }: {
    expectedNonce?: string;
    returnedNonce?: string;
  }) {
    return Effect.gen(function* () {
      yield* OIDCNonce.Helper.validateExpectedNonce(expectedNonce);
      yield* OIDCNonce.Helper.validateReturnedNonce(returnedNonce);
      yield* OIDCNonce.Helper.validateNonceMatch({
        expectedNonce: expectedNonce!,
        returnedNonce: returnedNonce!,
      });
    });
  }
}
