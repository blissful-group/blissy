import {
  AlgorithmReference,
  CryptoReference,
} from "@blissy-auth/crypto/source";
import { Effect } from "effect";

import {
  CodeChallengeMethodError,
  CodeChallengeVerificationError,
  CodeVerifierValidationError,
} from "./pkce.errors";
import { Helper } from "./pkce.helper";
import type {
  OAuth2PKCECodeChallengeMethod,
  OAuth2PKCECodeVerifierGenerationOptions,
} from "./pkce.types";

/**
 * Validates PKCE code verifiers and derives PKCE code challenges.
 */
export class OAuth2PKCE {
  private static Helper = Helper;

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
      const crypto = yield* CryptoReference;
      const bytes = new Uint8Array(byteLength);
      crypto.randomValues(bytes);
      const codeVerifier = OAuth2PKCE.Helper.encodeBase64Url(bytes);

      yield* OAuth2PKCE.validateCodeVerifier(codeVerifier);

      return codeVerifier;
    });
  }

  /**
   * Validates a PKCE code verifier according to RFC 7636 length and character rules.
   */
  static validateCodeVerifier(codeVerifier: string) {
    return Effect.gen(function* () {
      yield* OAuth2PKCE.Helper.validateCodeVerifierLength(codeVerifier);
      yield* OAuth2PKCE.Helper.validateCodeVerifierCharacters(codeVerifier);
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

      yield* OAuth2PKCE.Helper.validateCodeChallengeMethod(method);

      if (method === "plain") {
        return codeVerifier;
      }

      const algorithm = yield* AlgorithmReference;
      const crypto = yield* CryptoReference;
      const hash = yield* Effect.tryPromise(() =>
        crypto.digest(
          algorithm.digest[AlgorithmReference.SHA256],
          OAuth2PKCE.encoder.encode(codeVerifier),
        ),
      );

      return OAuth2PKCE.Helper.encodeBase64Url(new Uint8Array(hash));
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
}

export namespace OAuth2PKCE {
  export type CodeChallengeMethod = OAuth2PKCECodeChallengeMethod;
  export type CodeVerifierGenerationOptions =
    OAuth2PKCECodeVerifierGenerationOptions;
}
