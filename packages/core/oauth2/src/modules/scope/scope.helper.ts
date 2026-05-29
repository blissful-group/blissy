import { Effect, Schema } from "effect";

import { OAuth2ScopeValidationError } from "./scope.errors";
import { ScopeValueSchema } from "./scope.schema";
import type { OAuth2ScopeSet, OAuth2ScopeValue } from "./scope.types";

export class Helper {
  static validate(scope: OAuth2ScopeValue) {
    return Effect.mapError(
      Schema.decodeUnknown(ScopeValueSchema)(scope),
      () =>
        new OAuth2ScopeValidationError({
          message: "Invalid OAuth2 scope",
          scope,
        }),
    );
  }

  static validateAll(scopes: OAuth2ScopeSet) {
    return Effect.gen(function* () {
      for (const scope of scopes) {
        yield* Helper.validate(scope);
      }
    });
  }

  static unique(scopes: OAuth2ScopeSet) {
    return [...new Set(scopes)];
  }
}
