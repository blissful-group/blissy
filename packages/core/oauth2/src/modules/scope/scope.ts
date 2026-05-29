import { Effect } from "effect";

import { OAuth2ScopeValidationError } from "./scope.errors";
import { Helper } from "./scope.helper";
import type { OAuth2ScopeSet, OAuth2ScopeValue } from "./scope.types";

/**
 * Parses, formats, and compares OAuth 2.0 scope values.
 */
export class OAuth2Scope {
  private static Helper = Helper;

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

      yield* OAuth2Scope.Helper.validateAll(scopes);

      return OAuth2Scope.Helper.unique(scopes);
    });
  }

  /**
   * Formats scope values as a space-delimited OAuth 2.0 scope string.
   */
  static format(scopes: OAuth2ScopeSet) {
    return Effect.gen(function* () {
      yield* OAuth2Scope.Helper.validateAll(scopes);

      return OAuth2Scope.Helper.unique(scopes).join(" ");
    });
  }

  /**
   * Checks whether a scope set contains a specific required scope.
   */
  static includes(scopes: OAuth2ScopeSet, requiredScope: OAuth2ScopeValue) {
    return Effect.gen(function* () {
      yield* OAuth2Scope.Helper.validateAll(scopes);
      yield* OAuth2Scope.Helper.validate(requiredScope);

      return OAuth2Scope.Helper.unique(scopes).includes(requiredScope);
    });
  }

  /**
   * Checks whether a scope set contains every required scope.
   */
  static includesAll(scopes: OAuth2ScopeSet, requiredScopes: OAuth2ScopeSet) {
    return Effect.gen(function* () {
      yield* OAuth2Scope.Helper.validateAll(scopes);
      yield* OAuth2Scope.Helper.validateAll(requiredScopes);

      const uniqueScopes = OAuth2Scope.Helper.unique(scopes);

      return OAuth2Scope.Helper.unique(requiredScopes).every((requiredScope) =>
        uniqueScopes.includes(requiredScope),
      );
    });
  }

  /**
   * Checks whether a scope set contains at least one allowed scope.
   */
  static includesAny(scopes: OAuth2ScopeSet, allowedScopes: OAuth2ScopeSet) {
    return Effect.gen(function* () {
      yield* OAuth2Scope.Helper.validateAll(scopes);
      yield* OAuth2Scope.Helper.validateAll(allowedScopes);

      const uniqueScopes = OAuth2Scope.Helper.unique(scopes);

      return OAuth2Scope.Helper.unique(allowedScopes).some((allowedScope) =>
        uniqueScopes.includes(allowedScope),
      );
    });
  }

  /**
   * Returns the required scopes that are missing from a scope set.
   */
  static missing(scopes: OAuth2ScopeSet, requiredScopes: OAuth2ScopeSet) {
    return Effect.gen(function* () {
      yield* OAuth2Scope.Helper.validateAll(scopes);
      yield* OAuth2Scope.Helper.validateAll(requiredScopes);

      const uniqueScopes = OAuth2Scope.Helper.unique(scopes);

      return OAuth2Scope.Helper.unique(requiredScopes).filter(
        (requiredScope) => !uniqueScopes.includes(requiredScope),
      );
    });
  }
}

export namespace OAuth2Scope {
  export type Value = OAuth2ScopeValue;
  export type Set = OAuth2ScopeSet;
}
