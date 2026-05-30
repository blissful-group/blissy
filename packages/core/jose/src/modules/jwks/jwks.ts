import { Effect, Schema } from "effect";

import type { Filters } from "../../utils/filters";
import { JWKSKeyMatchError, JWKSParseError } from "./jwks.errors";
import { Helper } from "./jwks.helper";
import type { JWKSKeySchema } from "./jwks.schema";
import { JWKSSetSchema } from "./jwks.schema";

/**
 * Parses JWKS documents and selects matching keys.
 */
export class JWKS {
  private static Helper = Helper;

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
  static findKey({
    set,
    ...args
  }: Filters.Input & { set: typeof JWKSSetSchema.Type }) {
    return Effect.gen(function* () {
      const parsedSet = yield* JWKS.parse(set);

      return yield* JWKS.Helper.findSingleMatch({ args, keys: parsedSet.keys });
    });
  }
}

export declare namespace JWKS {
  export type Key = typeof JWKSKeySchema.Type;
  export type Set = typeof JWKSSetSchema.Type;
}
