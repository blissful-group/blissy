import { Effect, Schema } from "effect";

import { OAuth2ScopeValidationError } from "./scope.errors";
import { ScopeValueSchema } from "./scope.schema";

export class Helper {
  static validate(scope: typeof ScopeValueSchema.Type) {
    return Effect.mapError(
      Schema.decodeUnknown(ScopeValueSchema)(scope),
      () =>
        new OAuth2ScopeValidationError({
          message: "Invalid OAuth2 scope",
          scope,
        }),
    );
  }

  static validateAll(scopes: ReadonlyArray<typeof ScopeValueSchema.Type>) {
    return Effect.gen(function* () {
      for (const scope of scopes) {
        yield* Helper.validate(scope);
      }
    });
  }

  static unique(scopes: ReadonlyArray<typeof ScopeValueSchema.Type>) {
    return [...new Set(scopes)];
  }
}
