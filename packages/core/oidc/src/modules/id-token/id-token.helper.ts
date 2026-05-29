import type { JWT } from "@blissy-auth/jose/source";
import { Effect } from "effect";

import { compare } from "../../utils/compare";
import { OIDCIDTokenValidationError } from "./id-token.errors";

type OIDCIDTokenValidationMessage =
  | "Invalid ID token issuer"
  | "Invalid ID token subject"
  | "Invalid ID token audience"
  | "Invalid ID token expiration"
  | "Invalid ID token issued at"
  | "Invalid ID token nonce"
  | "Invalid ID token authorized party";

export class Helper {
  static validateIssuer({
    claims,
    issuer,
  }: {
    claims: JWT.Claims;
    issuer?: string;
  }) {
    if (typeof claims.iss !== "string" || claims.iss === "") {
      return Helper.fail("Invalid ID token issuer");
    }

    if (issuer === undefined) return Effect.void;
    if (claims.iss === issuer) return Effect.void;

    return Helper.fail("Invalid ID token issuer");
  }

  static validateSubject(claims: JWT.Claims) {
    if (typeof claims.sub === "string" && claims.sub !== "") return Effect.void;

    return Helper.fail("Invalid ID token subject");
  }

  static validateAudience({
    audience,
    claims,
  }: {
    claims: JWT.Claims;
    audience?: string;
  }) {
    if (
      typeof claims.aud !== "string" &&
      !(
        Array.isArray(claims.aud) &&
        claims.aud.length > 0 &&
        claims.aud.every((item) => typeof item === "string" && item !== "")
      )
    ) {
      return Helper.fail("Invalid ID token audience");
    }

    if (audience === undefined) return Effect.void;

    const audiences = Array.isArray(claims.aud) ? claims.aud : [claims.aud];

    if (!audiences.includes(audience)) {
      return Helper.fail("Invalid ID token audience");
    }

    if (audiences.length <= 1) return Effect.void;
    if (claims.azp === audience) return Effect.void;

    return Helper.fail("Invalid ID token authorized party");
  }

  static validateExpiration(claims: JWT.Claims) {
    if (typeof claims.exp === "number") return Effect.void;

    return Helper.fail("Invalid ID token expiration");
  }

  static validateIssuedAt(claims: JWT.Claims) {
    if (typeof claims.iat === "number") return Effect.void;

    return Helper.fail("Invalid ID token issued at");
  }

  static validateNonce({
    claims,
    expectedNonce,
  }: {
    claims: JWT.Claims;
    expectedNonce?: string;
  }) {
    if (expectedNonce === undefined) return Effect.void;
    if (typeof claims.nonce !== "string") {
      return Helper.fail("Invalid ID token nonce");
    }
    if (compare.string(expectedNonce, claims.nonce)) return Effect.void;

    return Helper.fail("Invalid ID token nonce");
  }

  static fail(message: OIDCIDTokenValidationMessage) {
    return Effect.fail(new OIDCIDTokenValidationError({ message }));
  }
}
