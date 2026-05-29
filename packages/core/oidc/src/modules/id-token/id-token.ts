import type { JWK } from "@blissy-auth/jose/source";
import { JWT } from "@blissy-auth/jose/source";
import { Effect } from "effect";

import { OIDCIDTokenValidationError } from "./id-token.errors";
import { Helper } from "./id-token.helper";

type OIDCIDTokenValue = {
  claims: JWT.Claims;
  header: JWT.Header;
};

/**
 * Parses, verifies, and validates OpenID Connect ID tokens.
 */
export class OIDCIDToken {
  private static Helper = Helper;

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

      const { claims } = decoded;
      yield* OIDCIDToken.Helper.validateIssuer({ claims });
      yield* OIDCIDToken.Helper.validateSubject(claims);
      yield* OIDCIDToken.Helper.validateAudience({ claims });
      yield* OIDCIDToken.Helper.validateExpiration(claims);
      yield* OIDCIDToken.Helper.validateIssuedAt(claims);

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

      const { claims } = decoded;
      yield* OIDCIDToken.Helper.validateIssuer({ claims, issuer });
      yield* OIDCIDToken.Helper.validateSubject(claims);
      yield* OIDCIDToken.Helper.validateAudience({ audience, claims });
      yield* OIDCIDToken.Helper.validateExpiration(claims);
      yield* OIDCIDToken.Helper.validateIssuedAt(claims);
      yield* OIDCIDToken.Helper.validateNonce({ claims, expectedNonce });

      return decoded;
    });
  }
}
