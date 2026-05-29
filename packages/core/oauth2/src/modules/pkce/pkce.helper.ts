import { Effect, Schema } from "effect";

import {
  CodeChallengeMethodError,
  CodeVerifierValidationError,
} from "./pkce.errors";
import {
  CodeChallengeMethodSchema,
  CodeVerifierCharactersSchema,
  CodeVerifierLengthSchema,
} from "./pkce.schema";

export class Helper {
  static validateCodeVerifierLength(codeVerifier: string) {
    return Effect.mapError(
      Schema.decodeUnknown(CodeVerifierLengthSchema)(codeVerifier),
      () =>
        new CodeVerifierValidationError({
          message: "Invalid PKCE code verifier length",
        }),
    );
  }

  static validateCodeVerifierCharacters(codeVerifier: string) {
    return Effect.mapError(
      Schema.decodeUnknown(CodeVerifierCharactersSchema)(codeVerifier),
      () =>
        new CodeVerifierValidationError({
          message: "Invalid PKCE code verifier characters",
        }),
    );
  }

  static validateCodeChallengeMethod(method: string) {
    if (Schema.is(CodeChallengeMethodSchema)(method)) return Effect.void;

    return Effect.fail(
      new CodeChallengeMethodError({
        message: "Unsupported PKCE code challenge method",
        method,
      }),
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
