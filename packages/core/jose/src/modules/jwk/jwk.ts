import {
  AlgorithmReference,
  CryptoReference,
} from "@blissy-auth/crypto/source";
import { Effect, Schema } from "effect";

import type { Filters } from "../../utils/filters";
import {
  JWKKeyImportError,
  JWKKeyMatchError,
  JWKSetParseError,
} from "./jwk.errors";
import { Helper } from "./jwk.helper";
import { JWKSetSchema } from "./jwk.schema";
import type { JWKKey, JWKSet, JWKValue } from "./jwk.types";

export {
  JWKKeyImportError,
  JWKKeyMatchError,
  JWKSetParseError,
} from "./jwk.errors";

/**
 * Parses JWK Sets and selects matching keys.
 */
export class JWK {
  private static Helper = Helper;

  static KeyMatchError = JWKKeyMatchError;
  static KeyImportError = JWKKeyImportError;
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

      return yield* JWK.Helper.findSingleMatch({ args, keys: parsedSet.keys });
    });
  }

  /**
   * Imports a public JWK for signature verification.
   */
  static importVerificationKey(key: JWKKey) {
    return Effect.gen(function* () {
      const algorithms = yield* AlgorithmReference;
      const algorithm = JWK.Helper.getAlgorithm(key, algorithms);

      if (algorithm === undefined) {
        return yield* Effect.fail(
          new JWKKeyImportError({ message: "Invalid JWK key" }),
        );
      }

      const crypto = yield* CryptoReference;

      return yield* Effect.tryPromise({
        catch: () => new JWKKeyImportError({ message: "Invalid JWK key" }),
        try: () =>
          crypto.importKey("jwk", key as JsonWebKey, algorithm, false, [
            "verify",
          ]),
      });
    });
  }
}

export declare namespace JWK {
  export type Value = JWKValue;
  export type Key = JWKKey;
  export type Set = JWKSet;
}
