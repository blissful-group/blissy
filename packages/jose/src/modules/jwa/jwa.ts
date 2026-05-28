import {
  AlgorithmReference,
  CryptoReference,
} from "@blissy-auth/crypto/source";
import { Effect } from "effect";

import {
  JWAAlgorithmNotSupportedError,
  JWAKeyCompatibilityError,
} from "./jwa.errors";
import type { JWAAlgorithm, JWAKey } from "./jwa.types";

/**
 * Signs and verifies payloads using JSON Web Algorithms.
 */
export class JWA {
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
      yield* JWA.validateAlgorithm(alg);
      const algorithms = yield* AlgorithmReference;
      yield* JWA.validateKeyCompatibility({ alg, algorithms, key });
      const crypto = yield* CryptoReference;
      const cryptoKey = yield* JWA.importKey({ key, usage: "sign" });
      const promise = crypto.sign(
        JWA.getSigningAlgorithm(alg, algorithms),
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
      yield* JWA.validateAlgorithm(alg);
      const algorithms = yield* AlgorithmReference;
      yield* JWA.validateKeyCompatibility({ alg, algorithms, key });
      const crypto = yield* CryptoReference;
      const cryptoKey = yield* JWA.importKey({ key, usage: "verify" });
      const promise = crypto.verify(
        JWA.getSigningAlgorithm(alg, algorithms),
        cryptoKey,
        new Uint8Array(signature),
        new Uint8Array(payload),
      );

      return yield* Effect.promise(() => promise);
    });
  }

  private static importKey({ key, usage }: { key: JWAKey; usage: KeyUsage }) {
    return Effect.gen(function* () {
      if (!(key instanceof Uint8Array)) return key;

      const algorithms = yield* AlgorithmReference;
      const crypto = yield* CryptoReference;
      const promise = crypto.importKey(
        "raw",
        new Uint8Array(key),
        algorithms.jwa[AlgorithmReference.HS256].importKey,
        false,
        [usage],
      );

      return yield* Effect.promise(() => promise);
    });
  }

  private static getSigningAlgorithm(
    alg: JWAAlgorithm,
    algorithms: AlgorithmReference.Service,
  ) {
    switch (alg) {
      case "HS256":
        return algorithms.jwa[AlgorithmReference.HS256].sign;
      case "RS256":
        return algorithms.jwa[AlgorithmReference.RS256].sign;
      case "ES256":
        return algorithms.jwa[AlgorithmReference.ES256].sign;
    }
  }

  private static validateAlgorithm(alg: string) {
    return Effect.gen(function* () {
      if (alg !== "HS256" && alg !== "RS256" && alg !== "ES256") {
        return yield* Effect.fail(
          new JWAAlgorithmNotSupportedError({
            message: `Unsupported JWA algorithm: "${alg}"`,
          }),
        );
      }
    });
  }

  private static validateKeyCompatibility({
    alg,
    algorithms,
    key,
  }: {
    alg: JWAAlgorithm;
    algorithms: AlgorithmReference.Service;
    key: JWAKey;
  }) {
    return Effect.gen(function* () {
      const isHmacKey = key instanceof Uint8Array;
      const isRsaKey =
        key instanceof CryptoKey &&
        key.algorithm.name ===
          algorithms.jwa[AlgorithmReference.RS256].importKey.name;
      const isEcKey =
        key instanceof CryptoKey &&
        key.algorithm.name ===
          algorithms.jwa[AlgorithmReference.ES256].importKey.name;

      if (alg === "HS256" && isHmacKey) return;
      if (alg === "RS256" && isRsaKey) return;
      if (alg === "ES256" && isEcKey) return;

      return yield* Effect.fail(
        new JWAKeyCompatibilityError({
          message: `Key is incompatible with JWA algorithm: "${alg}"`,
        }),
      );
    });
  }
}

export declare namespace JWA {
  export type Algorithm = JWAAlgorithm;
  export type Key = JWAKey;
}
