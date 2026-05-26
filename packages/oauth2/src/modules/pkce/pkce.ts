import { Effect, Schema } from "effect";

import { OAuth2Crypto } from "../../services/crypto/crypto";
import {
  CodeChallengeMethodError,
  CodeChallengeVerificationError,
  CodeVerifierValidationError,
} from "./pkce.errors";
import {
  CodeChallengeMethodSchema,
  CodeVerifierCharactersSchema,
  CodeVerifierLengthSchema,
} from "./pkce.schema";
import type {
  OAuth2PKCECodeChallengeMethod,
  OAuth2PKCECodeVerifierGenerationOptions,
} from "./pkce.types";

/**
 * Validates PKCE code verifiers and derives PKCE code challenges.
 */
export class OAuth2PKCE {
  /**
   * Error returned when a code challenge does not match its verifier.
   */
  static CodeChallengeVerificationError = CodeChallengeVerificationError;

  /**
   * Error returned when a code challenge method is unsupported.
   */
  static CodeChallengeMethodError = CodeChallengeMethodError;

  /**
   * Error returned when a code verifier is invalid.
   */
  static CodeVerifierValidationError = CodeVerifierValidationError;

  private static encoder = new TextEncoder();

  /**
   * Generates a cryptographically random PKCE code verifier.
   */
  static generateCodeVerifier({
    byteLength = 32,
  }: OAuth2PKCECodeVerifierGenerationOptions = {}) {
    return Effect.gen(function* () {
      const crypto = yield* OAuth2Crypto;
      const bytes = new Uint8Array(byteLength);
      crypto.randomValues(bytes);
      const codeVerifier = OAuth2PKCE.encodeBase64Url(bytes);

      yield* OAuth2PKCE.validateCodeVerifier(codeVerifier);

      return codeVerifier;
    });
  }

  /**
   * Validates a PKCE code verifier according to RFC 7636 length and character rules.
   */
  static validateCodeVerifier(codeVerifier: string) {
    return Effect.gen(function* () {
      yield* Effect.mapError(
        Schema.decodeUnknown(CodeVerifierLengthSchema)(codeVerifier),
        () =>
          new CodeVerifierValidationError({
            message: "Invalid PKCE code verifier length",
          }),
      );

      yield* Effect.mapError(
        Schema.decodeUnknown(CodeVerifierCharactersSchema)(codeVerifier),
        () =>
          new CodeVerifierValidationError({
            message: "Invalid PKCE code verifier characters",
          }),
      );
    });
  }

  /**
   * Creates a PKCE code challenge from a code verifier.
   */
  static createCodeChallenge({
    codeVerifier,
    method = "S256",
  }: {
    codeVerifier: string;
    method?: OAuth2PKCECodeChallengeMethod;
  }) {
    return Effect.gen(function* () {
      yield* OAuth2PKCE.validateCodeVerifier(codeVerifier);

      if (!Schema.is(CodeChallengeMethodSchema)(method)) {
        const error = new CodeChallengeMethodError({
          message: "Unsupported PKCE code challenge method",
          method,
        });

        return yield* Effect.fail(error);
      }

      if (method === "plain") {
        return codeVerifier;
      }

      const crypto = yield* OAuth2Crypto;
      const hash = yield* Effect.tryPromise(() =>
        crypto.digest("SHA-256", OAuth2PKCE.encoder.encode(codeVerifier)),
      );

      return OAuth2PKCE.encodeBase64Url(new Uint8Array(hash));
    });
  }

  /**
   * Verifies that a PKCE code challenge was derived from a code verifier.
   */
  static verifyCodeChallenge({
    codeChallenge,
    codeVerifier,
    method = "S256",
  }: {
    codeVerifier: string;
    codeChallenge: string;
    method?: OAuth2PKCECodeChallengeMethod;
  }) {
    return Effect.gen(function* () {
      const expectedCodeChallenge = yield* OAuth2PKCE.createCodeChallenge({
        codeVerifier,
        method,
      });

      if (expectedCodeChallenge !== codeChallenge) {
        const error = new CodeChallengeVerificationError({
          message: "Invalid PKCE code challenge",
          method,
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

export namespace OAuth2PKCE {
  export type CodeChallengeMethod = OAuth2PKCECodeChallengeMethod;
  export type CodeVerifierGenerationOptions =
    OAuth2PKCECodeVerifierGenerationOptions;
}
