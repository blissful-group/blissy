import { Effect } from "effect";

import { OAuth2ScopeValidationError } from "./scope.errors";
import { Helper } from "./scope.helper";
import type { ScopeValueSchema } from "./scope.schema";

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
        return [] satisfies ReadonlyArray<typeof ScopeValueSchema.Type>;
      }

      const scopes = trimmed.split(/\s+/u);

      yield* OAuth2Scope.Helper.validateAll(scopes);

      return OAuth2Scope.Helper.unique(scopes);
    });
  }

  /**
   * Formats scope values as a space-delimited OAuth 2.0 scope string.
   */
  static format(scopes: ReadonlyArray<typeof ScopeValueSchema.Type>) {
    return Effect.gen(function* () {
      yield* OAuth2Scope.Helper.validateAll(scopes);

      return OAuth2Scope.Helper.unique(scopes).join(" ");
    });
  }

  /**
   * Checks whether a scope set contains a specific required scope.
   */
  static includes(
    scopes: ReadonlyArray<typeof ScopeValueSchema.Type>,
    requiredScope: typeof ScopeValueSchema.Type,
  ) {
    return Effect.gen(function* () {
      yield* OAuth2Scope.Helper.validateAll(scopes);
      yield* OAuth2Scope.Helper.validate(requiredScope);

      return OAuth2Scope.Helper.unique(scopes).includes(requiredScope);
    });
  }

  /**
   * Checks whether a scope set contains every required scope.
   */
  static includesAll(
    scopes: ReadonlyArray<typeof ScopeValueSchema.Type>,
    requiredScopes: ReadonlyArray<typeof ScopeValueSchema.Type>,
  ) {
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
  static includesAny(
    scopes: ReadonlyArray<typeof ScopeValueSchema.Type>,
    allowedScopes: ReadonlyArray<typeof ScopeValueSchema.Type>,
  ) {
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
  static missing(
    scopes: ReadonlyArray<typeof ScopeValueSchema.Type>,
    requiredScopes: ReadonlyArray<typeof ScopeValueSchema.Type>,
  ) {
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
  export type Set = ReadonlyArray<typeof ScopeValueSchema.Type>;
}
