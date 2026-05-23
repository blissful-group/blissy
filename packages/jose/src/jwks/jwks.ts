import { Effect } from "effect";

import { JWKSKeyMatchError, JWKSParseError } from "./jwks.errors";
import type { JWKSKey, JWKSSet, JWKSValue } from "./jwks.types";

/**
 * Parses JWKS documents and selects matching keys.
 */
export class JWKS {
  static KeyMatchError = JWKSKeyMatchError;
  static ParseError = JWKSParseError;

  /**
   * Validates and returns a JWKS document.
   */
  static parse(input: unknown) {
    return Effect.gen(function* () {
      if (!JWKS.isSet(input)) {
        const error = new JWKSParseError({
          message: "Invalid JWKS: missing keys array",
        });

        return yield* Effect.fail(error);
      }

      return input;
    });
  }

  /**
   * Finds a single key in a JWKS document matching the given criteria.
   */
  static findKey({
    alg,
    kid,
    kty,
    set,
    use,
  }: {
    set: JWKSSet;
    kid?: string;
    alg?: string;
    kty?: string;
    use?: string;
  }) {
    return Effect.gen(function* () {
      const parsedSet = yield* JWKS.parse(set);
      const matches = parsedSet.keys.filter((key) => {
        if (kid !== undefined && key.kid !== kid) return false;
        if (alg !== undefined && key.alg !== alg) return false;
        if (kty !== undefined && key.kty !== kty) return false;
        if (use !== undefined && key.use !== use) return false;

        return true;
      });

      if (matches.length > 1) {
        const error = new JWKSKeyMatchError({
          message: "Multiple JWKS keys matched the given criteria",
        });

        return yield* Effect.fail(error);
      }

      return matches[0];
    });
  }

  private static isSet(input: unknown): input is JWKSSet {
    return (
      typeof input === "object" &&
      input !== null &&
      "keys" in input &&
      Array.isArray(input.keys)
    );
  }
}

export declare namespace JWKS {
  export type Value = JWKSValue;
  export type Key = JWKSKey;
  export type Set = JWKSSet;
}
