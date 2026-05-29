import { Effect } from "effect";

import type { JWAKey } from "../jwa/jwa.types";
import { JWK } from "../jwk/jwk";
import type { JWKSet } from "../jwk/jwk.types";
import { JWTClaimValidationError } from "./jwt.errors";
import type { JWTClaims, JWTHeader } from "./jwt.types";

export class Helper {
  static validateIssuer({
    claims,
    issuer,
  }: {
    claims: JWTClaims;
    issuer?: string;
  }) {
    if (issuer === undefined) return Effect.void;
    if (claims.iss === issuer) return Effect.void;

    const error = new JWTClaimValidationError({
      message: 'Invalid JWT claim "iss"',
    });

    return Effect.fail(error);
  }

  static validateSubject({
    claims,
    subject,
  }: {
    claims: JWTClaims;
    subject?: string;
  }) {
    if (subject === undefined) return Effect.void;
    if (claims.sub === subject) return Effect.void;

    const error = new JWTClaimValidationError({
      message: 'Invalid JWT claim "sub"',
    });

    return Effect.fail(error);
  }

  static validateAudience({
    audience,
    claims,
  }: {
    claims: JWTClaims;
    audience?: string;
  }) {
    if (audience === undefined) return Effect.void;
    if (claims.aud === audience) return Effect.void;
    if (Array.isArray(claims.aud) && claims.aud.includes(audience)) {
      return Effect.void;
    }

    const error = new JWTClaimValidationError({
      message: 'Invalid JWT claim "aud"',
    });

    return Effect.fail(error);
  }

  static validateExpiration({
    claims,
    clockTolerance,
    now,
  }: {
    claims: JWTClaims;
    now: number;
    clockTolerance: number;
  }) {
    if (claims.exp === undefined) return Effect.void;
    if (now <= claims.exp + clockTolerance) return Effect.void;

    const error = new JWTClaimValidationError({
      message: 'Invalid JWT claim "exp"',
    });

    return Effect.fail(error);
  }

  static validateNotBefore({
    claims,
    clockTolerance,
    now,
  }: {
    claims: JWTClaims;
    now: number;
    clockTolerance: number;
  }) {
    if (claims.nbf === undefined) return Effect.void;
    if (now >= claims.nbf - clockTolerance) return Effect.void;

    const error = new JWTClaimValidationError({
      message: 'Invalid JWT claim "nbf"',
    });

    return Effect.fail(error);
  }

  static validateIssuedAt({
    claims,
    clockTolerance,
    now,
  }: {
    claims: JWTClaims;
    now: number;
    clockTolerance: number;
  }) {
    if (claims.iat === undefined) return Effect.void;
    if (now >= claims.iat - clockTolerance) return Effect.void;

    const error = new JWTClaimValidationError({
      message: 'Invalid JWT claim "iat"',
    });

    return Effect.fail(error);
  }

  static resolveVerificationKey({
    header,
    jwks,
    key,
  }: {
    header: JWTHeader;
    key?: JWAKey;
    jwks?: JWKSet;
  }) {
    return Effect.gen(function* () {
      if (key !== undefined) return key;
      if (jwks === undefined) return undefined;

      const jwk = yield* JWK.findKey({
        alg: header.alg,
        kid: typeof header.kid === "string" ? header.kid : undefined,
        set: jwks,
        use: "sig",
      });

      if (jwk === undefined) return undefined;

      return yield* JWK.importVerificationKey(jwk);
    });
  }
}
