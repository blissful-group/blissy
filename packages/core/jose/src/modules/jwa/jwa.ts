import {
  AlgorithmReference,
  CryptoReference,
} from "@blissy-auth/crypto/source";
import { Effect } from "effect";

import {
  JWAAlgorithmNotSupportedError,
  JWAKeyCompatibilityError,
} from "./jwa.errors";
import { Helper } from "./jwa.helper";
import type { JWAAlgorithm, JWAKey } from "./jwa.types";

/**
 * Signs and verifies payloads using JSON Web Algorithms.
 */
export class JWA {
  private static Helper = Helper;

  static AlgorithmNotSupportedError = JWAAlgorithmNotSupportedError;
  static KeyCompatibilityError = JWAKeyCompatibilityError;

  /**
   * Signs a payload with the given algorithm and key.
   */
  static sign({
    alg,
    key,
    payload,
  }: {
    alg: JWAAlgorithm;
    key: JWAKey;
    payload: Uint8Array;
  }) {
    return Effect.gen(function* () {
      yield* JWA.Helper.validateAlgorithm(alg);
      const algorithms = yield* AlgorithmReference;
      yield* JWA.Helper.validateKeyCompatibility({ alg, algorithms, key });
      const crypto = yield* CryptoReference;
      const cryptoKey = yield* JWA.Helper.importKey({ key, usage: "sign" });
      const promise = crypto.sign(
        JWA.Helper.getSigningAlgorithm(alg, algorithms),
        cryptoKey,
        new Uint8Array(payload),
      );

      const signature = yield* Effect.promise(() => promise);

      return new Uint8Array(signature);
    });
  }

  /**
   * Verifies a signature with the given algorithm and key.
   */
  static verify({
    alg,
    key,
    payload,
    signature,
  }: {
    alg: JWAAlgorithm;
    key: JWAKey;
    payload: Uint8Array;
    signature: Uint8Array;
  }) {
    return Effect.gen(function* () {
      yield* JWA.Helper.validateAlgorithm(alg);
      const algorithms = yield* AlgorithmReference;
      yield* JWA.Helper.validateKeyCompatibility({ alg, algorithms, key });
      const crypto = yield* CryptoReference;
      const cryptoKey = yield* JWA.Helper.importKey({ key, usage: "verify" });
      const promise = crypto.verify(
        JWA.Helper.getSigningAlgorithm(alg, algorithms),
        cryptoKey,
        new Uint8Array(signature),
        new Uint8Array(payload),
      );

      return yield* Effect.promise(() => promise);
    });
  }
}

export declare namespace JWA {
  export type Algorithm = JWAAlgorithm;
  export type Key = JWAKey;
}
