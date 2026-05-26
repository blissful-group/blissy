import { Effect, Schema } from "effect";

import { Filters } from "../../utils/filters";
import { JWKKeyMatchError, JWKSetParseError } from "./jwk.errors";
import { JWKSetSchema } from "./jwk.schema";
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
    return Effect.mapError(
      Schema.decodeUnknown(JWKSetSchema)(input),
      () =>
        new JWKSetParseError({
          message: "Invalid JWK Set: missing keys array",
        }),
    );
  }

  /**
   * Finds a single key in a JWK Set matching the given criteria.
   */
  static findKey({ set, ...args }: Filters.Input & { set: JWKSet }) {
    return Effect.gen(function* () {
      const parsedSet = yield* JWK.parseSet(set);
      const matches = parsedSet.keys.filter(Filters.keys(args));

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
}

export declare namespace JWK {
  export type Value = JWKValue;
  export type Key = JWKKey;
  export type Set = JWKSet;
}
