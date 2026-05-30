import { AlgorithmReference } from "@blissy-auth/crypto";
import { Effect } from "effect";

import { Filters } from "../../utils/filters";
import { JWKKeyMatchError } from "./jwk.errors";
import type { JWKKeySchema } from "./jwk.schema";

export class Helper {
  static findSingleMatch({
    args,
    keys,
  }: {
    keys: ReadonlyArray<typeof JWKKeySchema.Type>;
    args: Filters.Input;
  }) {
    const matches = keys.filter((key) =>
      Filters.keys(args)(key as Filters.Input),
    );

    if (matches.length <= 1) return Effect.succeed(matches[0]);

    const error = new JWKKeyMatchError({
      message: "Multiple JWKs matched the given criteria",
    });

    return Effect.fail(error);
  }

  static getAlgorithm(
    key: typeof JWKKeySchema.Type,
    algorithms: AlgorithmReference.Service,
  ) {
    if (key.kty === "RSA") {
      return algorithms.jwa[AlgorithmReference.RS256].importKey;
    }

    if (key.kty === "EC" && key.crv === "P-256") {
      return algorithms.jwa[AlgorithmReference.ES256].importKey;
    }
  }
}
