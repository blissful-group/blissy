import { Effect } from "effect";

import { JWS } from "../jws/jws";
import { Base64 } from "../utils/base64";
import {
  JWTClaimValidationError,
  JWTDecodeError,
  JWTVerificationError,
} from "./jwt.errors";
import type {
  JWTAlgorithm,
  JWTClaims,
  JWTHeader,
  JWTHeaderValue,
} from "./jwt.types";

/**
 * Signs, verifies, and decodes JSON Web Tokens.
 */
export class JWT {
  static ClaimValidationError = JWTClaimValidationError;
  static DecodeError = JWTDecodeError;
  static VerificationError = JWTVerificationError;

  private static encoder = new TextEncoder();
  private static decoder = new TextDecoder();

  /**
   * Signs a JWT using HS256.
   */
  static sign({ claims, key }: { claims: JWTClaims; key: Uint8Array }) {
    return JWS.signCompact({
      key,
      payload: JWT.encoder.encode(JSON.stringify(claims)),
      protectedHeader: {
        alg: "HS256",
        typ: "JWT",
      },
    });
  }

  /**
   * Verifies a JWT and validates configured claims.
   */
  static verify({
    allowUnsecured = false,
    audience,
    clockTolerance = 0,
    issuer,
    key,
    now = Math.floor(Date.now() / 1000),
    subject,
    token,
  }: {
    token: string;
    key?: Uint8Array;
    issuer?: string;
    subject?: string;
    audience?: string;
    now?: number;
    clockTolerance?: number;
    allowUnsecured?: boolean;
  }) {
    return Effect.gen(function* () {
      const decoded = yield* JWT.decode({ token });

      if (decoded.header.alg === "none") {
        if (!allowUnsecured) {
          const error = new JWTVerificationError({
            message: "Unsigned JWTs are not allowed",
          });

          return yield* Effect.fail(error);
        }
      } else {
        if (key === undefined) {
          const error = new JWTVerificationError({
            message: "Invalid JWT signature",
          });

          return yield* Effect.fail(error);
        }

        const verified = yield* Effect.match(
          JWS.verifyCompact({ key, token }),
          {
            onFailure: () => false,
            onSuccess: () => true,
          },
        );

        if (!verified) {
          const error = new JWTVerificationError({
            message: "Invalid JWT signature",
          });

          return yield* Effect.fail(error);
        }
      }

      yield* JWT.validateClaims({
        audience,
        claims: decoded.claims,
        clockTolerance,
        issuer,
        now,
        subject,
      });

      return decoded;
    });
  }

  /**
   * Decodes a JWT without verifying its signature.
   */
  static decode({ token }: { token: string }) {
    return Effect.gen(function* () {
      const segments = token.split(".");

      if (segments.length !== 3) {
        const error = new JWTDecodeError({ message: "Invalid JWT" });

        return yield* Effect.fail(error);
      }

      const [headerSegment, payloadSegment] = segments;

      try {
        const headerBytes = yield* Base64.decode(headerSegment!);
        const payloadBytes = yield* Base64.decode(payloadSegment!);
        const header = JSON.parse(JWT.decoder.decode(headerBytes)) as JWTHeader;
        const decoded = JWT.decoder.decode(payloadBytes);
        const claims = JSON.parse(decoded) as JWTClaims;

        return { claims, header };
      } catch {
        const error = new JWTDecodeError({ message: "Invalid JWT" });

        return yield* Effect.fail(error);
      }
    });
  }

  private static validateClaims({
    audience,
    claims,
    clockTolerance,
    issuer,
    now,
    subject,
  }: {
    claims: JWTClaims;
    issuer?: string;
    subject?: string;
    audience?: string;
    now: number;
    clockTolerance: number;
  }) {
    return Effect.gen(function* () {
      if (issuer !== undefined && claims.iss !== issuer) {
        const error = new JWTClaimValidationError({
          message: 'Invalid JWT claim "iss"',
        });

        return yield* Effect.fail(error);
      }

      if (subject !== undefined && claims.sub !== subject) {
        const error = new JWTClaimValidationError({
          message: 'Invalid JWT claim "sub"',
        });

        return yield* Effect.fail(error);
      }

      if (audience !== undefined) {
        const validAudience =
          claims.aud === audience ||
          (Array.isArray(claims.aud) && claims.aud.includes(audience));

        if (!validAudience) {
          const error = new JWTClaimValidationError({
            message: 'Invalid JWT claim "aud"',
          });

          return yield* Effect.fail(error);
        }
      }

      if (claims.exp !== undefined && now > claims.exp + clockTolerance) {
        const error = new JWTClaimValidationError({
          message: 'Invalid JWT claim "exp"',
        });

        return yield* Effect.fail(error);
      }

      if (claims.nbf !== undefined && now < claims.nbf - clockTolerance) {
        const error = new JWTClaimValidationError({
          message: 'Invalid JWT claim "nbf"',
        });

        return yield* Effect.fail(error);
      }

      if (claims.iat !== undefined && now < claims.iat - clockTolerance) {
        const error = new JWTClaimValidationError({
          message: 'Invalid JWT claim "iat"',
        });

        return yield* Effect.fail(error);
      }
    });
  }
}

export declare namespace JWT {
  export type Algorithm = JWTAlgorithm;
  export type Claims = JWTClaims;
  export type Header = JWTHeader;
  export type HeaderValue = JWTHeaderValue;
}
