import { Effect, Schema } from "effect";

import { OAuth2ScopeValidationError } from "./scope.errors";
import { ScopeValueSchema } from "./scope.schema";
import type { OAuth2ScopeSet, OAuth2ScopeValue } from "./scope.types";

/**
 * Parses, formats, and compares OAuth 2.0 scope values.
 */
export class OAuth2Scope {
  /**
   * Error returned when a scope value is invalid.
   */
  static ValidationError = OAuth2ScopeValidationError;

  /**
   * Parses a space-delimited OAuth 2.0 scope string into individual scope values.
   */
  static parse(input: string) {
    return Effect.gen(function* () {
      const trimmed = input.trim();

      if (trimmed === "") {
        return [] satisfies OAuth2ScopeSet;
      }

      const scopes = trimmed.split(/\s+/u);

      yield* OAuth2Scope.validateAll(scopes);

      return OAuth2Scope.unique(scopes);
    });
  }

  /**
   * Formats scope values as a space-delimited OAuth 2.0 scope string.
   */
  static format(scopes: OAuth2ScopeSet) {
    return Effect.gen(function* () {
      yield* OAuth2Scope.validateAll(scopes);

      return OAuth2Scope.unique(scopes).join(" ");
    });
  }

  /**
   * Checks whether a scope set contains a specific required scope.
   */
  static includes(scopes: OAuth2ScopeSet, requiredScope: OAuth2ScopeValue) {
    return Effect.gen(function* () {
      yield* OAuth2Scope.validateAll(scopes);
      yield* OAuth2Scope.validate(requiredScope);

      return OAuth2Scope.unique(scopes).includes(requiredScope);
    });
  }

  /**
   * Checks whether a scope set contains every required scope.
   */
  static includesAll(scopes: OAuth2ScopeSet, requiredScopes: OAuth2ScopeSet) {
    return Effect.gen(function* () {
      yield* OAuth2Scope.validateAll(scopes);
      yield* OAuth2Scope.validateAll(requiredScopes);

      const uniqueScopes = OAuth2Scope.unique(scopes);

      return OAuth2Scope.unique(requiredScopes).every((requiredScope) =>
        uniqueScopes.includes(requiredScope),
      );
    });
  }

  /**
   * Checks whether a scope set contains at least one allowed scope.
   */
  static includesAny(scopes: OAuth2ScopeSet, allowedScopes: OAuth2ScopeSet) {
    return Effect.gen(function* () {
      yield* OAuth2Scope.validateAll(scopes);
      yield* OAuth2Scope.validateAll(allowedScopes);

      const uniqueScopes = OAuth2Scope.unique(scopes);

      return OAuth2Scope.unique(allowedScopes).some((allowedScope) =>
        uniqueScopes.includes(allowedScope),
      );
    });
  }

  /**
   * Returns the required scopes that are missing from a scope set.
   */
  static missing(scopes: OAuth2ScopeSet, requiredScopes: OAuth2ScopeSet) {
    return Effect.gen(function* () {
      yield* OAuth2Scope.validateAll(scopes);
      yield* OAuth2Scope.validateAll(requiredScopes);

      const uniqueScopes = OAuth2Scope.unique(scopes);

      return OAuth2Scope.unique(requiredScopes).filter(
        (requiredScope) => !uniqueScopes.includes(requiredScope),
      );
    });
  }

  private static validate(scope: OAuth2ScopeValue) {
    return Effect.mapError(
      Schema.decodeUnknown(ScopeValueSchema)(scope),
      () =>
        new OAuth2ScopeValidationError({
          message: "Invalid OAuth2 scope",
          scope,
        }),
    );
  }

  private static validateAll(scopes: OAuth2ScopeSet) {
    return Effect.gen(function* () {
      for (const scope of scopes) {
        yield* OAuth2Scope.validate(scope);
      }
    });
  }

  private static unique(scopes: OAuth2ScopeSet) {
    return [...new Set(scopes)];
  }
}

export namespace OAuth2Scope {
  export type Value = OAuth2ScopeValue;
  export type Set = OAuth2ScopeSet;
}
