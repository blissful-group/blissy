import { Effect } from "effect";

import {
  CODE_VERIFIER_MAX_LENGTH,
  CODE_VERIFIER_MIN_LENGTH,
  CODE_VERIFIER_PATTERN,
} from "./pkce.constants";
import {
  CodeChallengeMethodError,
  CodeChallengeVerificationError,
  CodeVerifierValidationError,
} from "./pkce.errors";
import type { OAuth2PKCECodeChallengeMethod } from "./pkce.types";

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
   * Validates a PKCE code verifier according to RFC 7636 length and character rules.
   */
  static validateCodeVerifier(codeVerifier: string) {
    return Effect.gen(function* () {
      if (
        codeVerifier.length < CODE_VERIFIER_MIN_LENGTH ||
        codeVerifier.length > CODE_VERIFIER_MAX_LENGTH
      ) {
        const error = new CodeVerifierValidationError({
          message: "Invalid PKCE code verifier length",
        });

        return yield* Effect.fail(error);
      }

      if (!CODE_VERIFIER_PATTERN.test(codeVerifier)) {
        const error = new CodeVerifierValidationError({
          message: "Invalid PKCE code verifier characters",
        });

        return yield* Effect.fail(error);
      }
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

      if (method === "plain") {
        return codeVerifier;
      }

      if (method === "S256") {
        const digest = yield* Effect.tryPromise(() =>
          globalThis.crypto.subtle.digest(
            "SHA-256",
            OAuth2PKCE.encoder.encode(codeVerifier),
          ),
        );

        return OAuth2PKCE.encodeBase64Url(new Uint8Array(digest));
      }

      const error = new CodeChallengeMethodError({
        message: "Unsupported PKCE code challenge method",
        method,
      });

      return yield* Effect.fail(error);
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
}
