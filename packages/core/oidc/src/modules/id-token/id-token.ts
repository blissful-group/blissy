import type { JWK } from "@blissy-auth/jose/source";
import { JWT } from "@blissy-auth/jose/source";
import { Effect } from "effect";

import { compare } from "../../utils/compare";
import { OIDCIDTokenValidationError } from "./id-token.errors";

type OIDCIDTokenValue = {
  claims: JWT.Claims;
  header: JWT.Header;
};

/**
 * Parses, verifies, and validates OpenID Connect ID tokens.
 */
export class OIDCIDToken {
  /**
   * Error returned when an ID token's OIDC claims are invalid.
   */
  static ValidationError = OIDCIDTokenValidationError;

  /**
   * Decodes an ID token without verifying its signature.
   */
  static decode({
    token,
  }: {
    token: string;
  }): Effect.Effect<OIDCIDTokenValue, unknown> {
    return Effect.gen(function* () {
      const decoded = yield* JWT.decode({ token });

      yield* OIDCIDToken.validateClaims({ claims: decoded.claims });

      return decoded;
    });
  }

  /**
   * Verifies an ID token signature and validates standard OIDC claims.
   */
  static verify({
    audience,
    clockTolerance = 0,
    expectedNonce,
    issuer,
    jwks,
    key,
    now = Math.floor(Date.now() / 1000),
    token,
  }: {
    token: string;
    issuer: string;
    audience: string;
    expectedNonce?: string;
    key?: CryptoKey | Uint8Array;
    jwks?: JWK.Set;
    now?: number;
    clockTolerance?: number;
  }): Effect.Effect<OIDCIDTokenValue, unknown> {
    return Effect.gen(function* () {
      const decoded = yield* JWT.verify({
        audience,
        clockTolerance,
        issuer,
        jwks,
        key,
        now,
        token,
      });

      yield* OIDCIDToken.validateClaims({
        audience,
        claims: decoded.claims,
        expectedNonce,
        issuer,
      });

      return decoded;
    });
  }

  private static validateClaims({
    audience,
    claims,
    expectedNonce,
    issuer,
  }: {
    claims: JWT.Claims;
    issuer?: string;
    audience?: string;
    expectedNonce?: string;
  }) {
    return Effect.gen(function* () {
      if (typeof claims.iss !== "string" || claims.iss === "") {
        return yield* OIDCIDToken.fail("Invalid ID token issuer");
      }

      if (issuer !== undefined && claims.iss !== issuer) {
        return yield* OIDCIDToken.fail("Invalid ID token issuer");
      }

      if (typeof claims.sub !== "string" || claims.sub === "") {
        return yield* OIDCIDToken.fail("Invalid ID token subject");
      }

      if (
        typeof claims.aud !== "string" &&
        !(
          Array.isArray(claims.aud) &&
          claims.aud.length > 0 &&
          claims.aud.every((item) => typeof item === "string" && item !== "")
        )
      ) {
        return yield* OIDCIDToken.fail("Invalid ID token audience");
      }

      if (audience !== undefined) {
        const audiences = Array.isArray(claims.aud) ? claims.aud : [claims.aud];

        if (!audiences.includes(audience)) {
          return yield* OIDCIDToken.fail("Invalid ID token audience");
        }

        if (audiences.length > 1 && claims.azp !== audience) {
          return yield* OIDCIDToken.fail("Invalid ID token authorized party");
        }
      }

      if (typeof claims.exp !== "number") {
        return yield* OIDCIDToken.fail("Invalid ID token expiration");
      }

      if (typeof claims.iat !== "number") {
        return yield* OIDCIDToken.fail("Invalid ID token issued at");
      }

      if (expectedNonce !== undefined) {
        if (typeof claims.nonce !== "string") {
          return yield* OIDCIDToken.fail("Invalid ID token nonce");
        }

        if (!compare.string(expectedNonce, claims.nonce)) {
          return yield* OIDCIDToken.fail("Invalid ID token nonce");
        }
      }
    });
  }

  private static fail(
    message:
      | "Invalid ID token issuer"
      | "Invalid ID token subject"
      | "Invalid ID token audience"
      | "Invalid ID token expiration"
      | "Invalid ID token issued at"
      | "Invalid ID token nonce"
      | "Invalid ID token authorized party",
  ) {
    return Effect.fail(new OIDCIDTokenValidationError({ message }));
  }
}
