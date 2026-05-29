import { AlgorithmReference } from "@blissy-auth/crypto/source";
import { Effect } from "effect";

import { Filters } from "../../utils/filters";
import { JWKKeyMatchError } from "./jwk.errors";
import type { JWKKey } from "./jwk.types";

export class Helper {
  static findSingleMatch({
    args,
    keys,
  }: {
    keys: ReadonlyArray<JWKKey>;
    args: Filters.Input;
  }) {
    const matches = keys.filter(Filters.keys(args));

    if (matches.length <= 1) return Effect.succeed(matches[0]);

    const error = new JWKKeyMatchError({
      message: "Multiple JWKs matched the given criteria",
    });

    return Effect.fail(error);
  }

  static getAlgorithm(key: JWKKey, algorithms: AlgorithmReference.Service) {
    if (key.kty === "RSA") {
      return algorithms.jwa[AlgorithmReference.RS256].importKey;
    }

    if (key.kty === "EC" && key.crv === "P-256") {
      return algorithms.jwa[AlgorithmReference.ES256].importKey;
    }
  }
}
