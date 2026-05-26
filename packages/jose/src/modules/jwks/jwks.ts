import { Effect, Schema } from "effect";

import { Filters } from "../../utils/filters";
import { JWKSKeyMatchError, JWKSParseError } from "./jwks.errors";
import { JWKSSetSchema } from "./jwks.schema";
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
    return Effect.mapError(
      Schema.decodeUnknown(JWKSSetSchema)(input),
      () =>
        new JWKSParseError({
          message: "Invalid JWKS: missing keys array",
        }),
    );
  }

  /**
   * Finds a single key in a JWKS document matching the given criteria.
   */
  static findKey({ set, ...args }: Filters.Input & { set: JWKSSet }) {
    return Effect.gen(function* () {
      const parsedSet = yield* JWKS.parse(set);
      const matches = parsedSet.keys.filter(Filters.keys(args));

      if (matches.length > 1) {
        const error = new JWKSKeyMatchError({
          message: "Multiple JWKS keys matched the given criteria",
        });

        return yield* Effect.fail(error);
      }

      return matches[0];
    });
  }
}

export declare namespace JWKS {
  export type Value = JWKSValue;
  export type Key = JWKSKey;
  export type Set = JWKSSet;
}
