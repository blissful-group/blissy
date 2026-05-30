import { Effect } from "effect";

import { Filters } from "../../utils/filters";
import { JWKSKeyMatchError } from "./jwks.errors";
import type { JWKSKeySchema } from "./jwks.schema";

export class Helper {
  static findSingleMatch({
    args,
    keys,
  }: {
    keys: ReadonlyArray<typeof JWKSKeySchema.Type>;
    args: Filters.Input;
  }) {
    const matches = keys.filter((key) =>
      Filters.keys(args)(key as Filters.Input),
    );

    if (matches.length <= 1) return Effect.succeed(matches[0]);

    const error = new JWKSKeyMatchError({
      message: "Multiple JWKS keys matched the given criteria",
    });

    return Effect.fail(error);
  }
}
