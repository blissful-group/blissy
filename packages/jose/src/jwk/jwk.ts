import { Effect } from "effect";

import { JWKKeyMatchError, JWKSetParseError } from "./jwk.errors";
import type { JWKKey, JWKSet, JWKValue } from "./jwk.types";

export { JWKKeyMatchError, JWKSetParseError } from "./jwk.errors";

/**
 * Parses JWK Sets and selects matching keys.
 */
export class JWK {
  static KeyMatchError = JWKKeyMatchError;
  static SetParseError = JWKSetParseError;

  /**
   * Validates and returns a JWK Set.
   */
  static parseSet(input: unknown) {
    return Effect.gen(function* () {
      if (!JWK.isSet(input)) {
        return yield* Effect.fail(
          new JWKSetParseError({
            message: "Invalid JWK Set: missing keys array",
          }),
        );
      }

      return input;
    });
  }

  /**
   * Finds a single key in a JWK Set matching the given criteria.
   */
  static findKey({
    alg,
    kid,
    kty,
    set,
    use,
  }: {
    set: JWKSet;
    kid?: string;
    alg?: string;
    kty?: string;
    use?: string;
  }) {
    return Effect.gen(function* () {
      const parsedSet = yield* JWK.parseSet(set);
      const matches = parsedSet.keys.filter((key) => {
        if (kid !== undefined && key.kid !== kid) {
          return false;
        }

        if (alg !== undefined && key.alg !== alg) {
          return false;
        }

        if (kty !== undefined && key.kty !== kty) {
          return false;
        }

        if (use !== undefined && key.use !== use) {
          return false;
        }

        return true;
      });

      if (matches.length > 1) {
        return yield* Effect.fail(
          new JWKKeyMatchError({
            message: "Multiple JWKs matched the given criteria",
          }),
        );
      }

      return matches[0];
    });
  }

  private static isSet(input: unknown): input is JWKSet {
    return (
      typeof input === "object" &&
      input !== null &&
      "keys" in input &&
      Array.isArray(input.keys)
    );
  }
}

export declare namespace JWK {
  export type Value = JWKValue;
  export type Key = JWKKey;
  export type Set = JWKSet;
}
