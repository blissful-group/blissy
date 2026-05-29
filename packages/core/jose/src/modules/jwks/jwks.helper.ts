import { Effect } from "effect";

import { Filters } from "../../utils/filters";
import { JWKSKeyMatchError } from "./jwks.errors";
import type { JWKSKey } from "./jwks.types";

export class Helper {
  static findSingleMatch({
    args,
    keys,
  }: {
    keys: ReadonlyArray<JWKSKey>;
    args: Filters.Input;
  }) {
    const matches = keys.filter(Filters.keys(args));

    if (matches.length <= 1) return Effect.succeed(matches[0]);

    const error = new JWKSKeyMatchError({
      message: "Multiple JWKS keys matched the given criteria",
    });

    return Effect.fail(error);
  }
}
