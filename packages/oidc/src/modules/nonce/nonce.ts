import { CryptoReference } from "@blissy-auth/crypto/source";
import { Effect, Schema } from "effect";

import { compare } from "../../utils/compare";
import { NONCE_DEFAULT_BYTE_LENGTH } from "./nonce.constants";
import {
  OIDCNonceGenerationError,
  OIDCNonceValidationError,
} from "./nonce.errors";
import { NonceByteLengthSchema } from "./nonce.schema";

/**
 * Generates and validates OpenID Connect nonce values.
 */
export class OIDCNonce {
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

      yield* Effect.mapError(
        Schema.decodeUnknown(NonceByteLengthSchema)(byteLength),
        () =>
          new OIDCNonceGenerationError({
            byteLength,
            message: "Invalid OIDC nonce byte length",
          }),
      );

      const bytes = new Uint8Array(byteLength);
      crypto.randomValues(bytes);

      return OIDCNonce.encodeBase64Url(bytes);
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
      if (expectedNonce === undefined || expectedNonce === "") {
        return yield* Effect.fail(
          new OIDCNonceValidationError({ message: "Missing OIDC nonce" }),
        );
      }

      if (returnedNonce === undefined || returnedNonce === "") {
        return yield* Effect.fail(
          new OIDCNonceValidationError({ message: "Missing OIDC nonce" }),
        );
      }

      if (!compare.string(expectedNonce, returnedNonce)) {
        return yield* Effect.fail(
          new OIDCNonceValidationError({ message: "Invalid OIDC nonce" }),
        );
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
