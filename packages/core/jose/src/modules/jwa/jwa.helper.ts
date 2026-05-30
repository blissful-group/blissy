import {
  AlgorithmReference,
  CryptoReference,
} from "@blissy-auth/crypto/source";
import { Effect } from "effect";

import type { JWA } from "./jwa";
import {
  JWAAlgorithmNotSupportedError,
  JWAKeyCompatibilityError,
} from "./jwa.errors";

export class Helper {
  static importKey({ key, usage }: { key: JWA.Key; usage: KeyUsage }) {
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

  static getSigningAlgorithm(
    alg: JWA.Algorithm,
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

  static validateAlgorithm(alg: string) {
    if (alg === "HS256") return Effect.void;
    if (alg === "RS256") return Effect.void;
    if (alg === "ES256") return Effect.void;

    const error = new JWAAlgorithmNotSupportedError({
      message: `Unsupported JWA algorithm: "${alg}"`,
    });

    return Effect.fail(error);
  }

  static validateKeyCompatibility({
    alg,
    algorithms,
    key,
  }: {
    alg: JWA.Algorithm;
    algorithms: AlgorithmReference.Service;
    key: JWA.Key;
  }) {
    const isHmacKey = key instanceof Uint8Array;
    const isRsaKey =
      key instanceof CryptoKey &&
      key.algorithm.name ===
        algorithms.jwa[AlgorithmReference.RS256].importKey.name;
    const isEcKey =
      key instanceof CryptoKey &&
      key.algorithm.name ===
        algorithms.jwa[AlgorithmReference.ES256].importKey.name;

    if (alg === "HS256" && isHmacKey) return Effect.void;
    if (alg === "RS256" && isRsaKey) return Effect.void;
    if (alg === "ES256" && isEcKey) return Effect.void;

    const error = new JWAKeyCompatibilityError({
      message: `Key is incompatible with JWA algorithm: "${alg}"`,
    });

    return Effect.fail(error);
  }
}
