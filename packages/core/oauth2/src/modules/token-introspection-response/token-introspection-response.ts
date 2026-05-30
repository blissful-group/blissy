import { Effect } from "effect";

import type { OAuth2Scope } from "../scope/scope";
import { OAuth2TokenIntrospectionResponseValidationError } from "./token-introspection-response.errors";
import { Helper } from "./token-introspection-response.helper";
import type {
  IntrospectionStringListClaimSchema,
  IntrospectionTimestampClaimSchema,
} from "./token-introspection-response.schema";

/**
 * Parses OAuth 2.0 token introspection endpoint JSON responses.
 */
export class OAuth2TokenIntrospectionResponse {
  private static Helper = Helper;

  /**
   * Error returned when a token introspection response is invalid.
   */
  static ValidationError = OAuth2TokenIntrospectionResponseValidationError;

  /**
   * Parses an introspection response for active and inactive tokens.
   */
  static parse(input: unknown) {
    return Effect.gen(function* () {
      const response =
        yield* OAuth2TokenIntrospectionResponse.Helper.parseRecord(input);
      const active = yield* Helper.active(response);

      if (!active) return { active };

      return {
        active,
        aud: yield* Helper.aud(response),
        clientId: yield* Helper.clientId(response),
        exp: yield* Helper.exp(response),
        iat: yield* Helper.iat(response),
        iss: yield* Helper.iss(response),
        jti: yield* Helper.jti(response),
        nbf: yield* Helper.nbf(response),
        scope: yield* Helper.scope(response),
        sub: yield* Helper.sub(response),
        tokenType: yield* Helper.tokenType(response),
        username: yield* Helper.username(response),
      };
    });
  }
}

export namespace OAuth2TokenIntrospectionResponse {
  export type Inactive = {
    active: false;
  };

  export type Active = {
    active: true;
    scope?: OAuth2Scope.Set;
    clientId?: string;
    username?: string;
    tokenType?: string;
    exp?: typeof IntrospectionTimestampClaimSchema.Type;
    iat?: typeof IntrospectionTimestampClaimSchema.Type;
    nbf?: typeof IntrospectionTimestampClaimSchema.Type;
    sub?: string;
    aud?: typeof IntrospectionStringListClaimSchema.Type;
    iss?: string;
    jti?: string;
  };

  export type Value = Inactive | Active;
}
