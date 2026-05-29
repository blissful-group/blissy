import { Effect } from "effect";

import { Base64 } from "../../utils/base64";
import type { JWAKey } from "../jwa/jwa.types";
import type { JWKSet } from "../jwk/jwk.types";
import { JWS } from "../jws/jws";
import {
  JWTClaimValidationError,
  JWTDecodeError,
  JWTVerificationError,
} from "./jwt.errors";
import { Helper } from "./jwt.helper";
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
  private static Helper = Helper;

  static ClaimValidationError = JWTClaimValidationError;
  static DecodeError = JWTDecodeError;
  static VerificationError = JWTVerificationError;

  private static encoder = new TextEncoder();
  private static decoder = new TextDecoder();

  /**
   * Signs a JWT.
   */
  static sign({
    alg = "HS256",
    claims,
    key,
  }: {
    claims: JWTClaims;
    key: JWAKey;
    alg?: Exclude<JWTAlgorithm, "none">;
  }) {
    return JWS.signCompact({
      key,
      payload: JWT.encoder.encode(JSON.stringify(claims)),
      protectedHeader: {
        alg,
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
    jwks,
    key,
    now = Math.floor(Date.now() / 1000),
    subject,
    token,
  }: {
    token: string;
    key?: JWAKey;
    jwks?: JWKSet;
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
        const verificationKey = yield* JWT.Helper.resolveVerificationKey({
          header: decoded.header,
          jwks,
          key,
        });

        if (verificationKey === undefined) {
          const error = new JWTVerificationError({
            message: "Invalid JWT signature",
          });

          return yield* Effect.fail(error);
        }

        const verified = yield* Effect.match(
          JWS.verifyCompact({ key: verificationKey, token }),
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

      const { claims } = decoded;
      yield* Helper.validateIssuer({ claims, issuer });
      yield* Helper.validateSubject({ claims, subject });
      yield* Helper.validateAudience({ claims, audience });
      yield* Helper.validateExpiration({ claims, clockTolerance, now });
      yield* Helper.validateNotBefore({ claims, clockTolerance, now });
      yield* Helper.validateIssuedAt({ claims, clockTolerance, now });

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
}

export declare namespace JWT {
  export type Algorithm = JWTAlgorithm;
  export type Claims = JWTClaims;
  export type Header = JWTHeader;
  export type HeaderValue = JWTHeaderValue;
}
