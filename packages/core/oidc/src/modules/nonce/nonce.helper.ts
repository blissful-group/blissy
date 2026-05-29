import { Effect, Schema } from "effect";

import { compare } from "../../utils/compare";
import {
  OIDCNonceGenerationError,
  OIDCNonceValidationError,
} from "./nonce.errors";
import { NonceByteLengthSchema } from "./nonce.schema";

export class Helper {
  static validateByteLength(byteLength: number) {
    return Effect.mapError(
      Schema.decodeUnknown(NonceByteLengthSchema)(byteLength),
      () =>
        new OIDCNonceGenerationError({
          byteLength,
          message: "Invalid OIDC nonce byte length",
        }),
    );
  }

  static validateExpectedNonce(expectedNonce?: string) {
    if (expectedNonce !== undefined && expectedNonce !== "") return Effect.void;

    return Effect.fail(
      new OIDCNonceValidationError({ message: "Missing OIDC nonce" }),
    );
  }

  static validateReturnedNonce(returnedNonce?: string) {
    if (returnedNonce !== undefined && returnedNonce !== "") return Effect.void;

    return Effect.fail(
      new OIDCNonceValidationError({ message: "Missing OIDC nonce" }),
    );
  }

  static validateNonceMatch({
    expectedNonce,
    returnedNonce,
  }: {
    expectedNonce: string;
    returnedNonce: string;
  }) {
    if (compare.string(expectedNonce, returnedNonce)) return Effect.void;

    return Effect.fail(
      new OIDCNonceValidationError({ message: "Invalid OIDC nonce" }),
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
