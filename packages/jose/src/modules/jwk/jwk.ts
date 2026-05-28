import { Effect, Schema } from "effect";

import { Filters } from "../../utils/filters";
import {
  JWKKeyImportError,
  JWKKeyMatchError,
  JWKSetParseError,
} from "./jwk.errors";
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

  /**
   * Imports a public JWK for signature verification.
   */
  static importVerificationKey(key: JWKKey) {
    return Effect.gen(function* () {
      const alg = JWK.getAlgorithm(key);

      if (alg === undefined) {
        return yield* Effect.fail(
          new JWKKeyImportError({ message: "Invalid JWK key" }),
        );
      }

      return yield* Effect.tryPromise({
        catch: () => new JWKKeyImportError({ message: "Invalid JWK key" }),
        try: () =>
          crypto.subtle.importKey("jwk", key as JsonWebKey, alg, false, [
            "verify",
          ]),
      });
    });
  }

  private static getAlgorithm(key: JWKKey) {
    if (key.kty === "RSA") {
      return { hash: "SHA-256", name: "RSASSA-PKCS1-v1_5" } as const;
    }

    if (key.kty === "EC" && key.crv === "P-256") {
      return { name: "ECDSA", namedCurve: "P-256" } as const;
    }
  }
}

export declare namespace JWK {
  export type Value = JWKValue;
  export type Key = JWKKey;
  export type Set = JWKSet;
}
