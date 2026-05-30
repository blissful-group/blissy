import { Effect } from "effect";

import type { OAuth2Scope } from "../scope/scope";
import { OAuth2TokenResponseValidationError } from "./token-response.errors";
import { Helper } from "./token-response.helper";
import type { ExpiresInSchema } from "./token-response.schema";

/**
 * Parses OAuth 2.0 token endpoint JSON responses.
 */
export class OAuth2TokenResponse {
  private static Helper = Helper;

  /**
   * Error returned when a token response is invalid.
   */
  static ValidationError = OAuth2TokenResponseValidationError;

  /**
   * Parses either a successful token response or an OAuth token error response.
   */
  static parse(input: unknown) {
    return Effect.gen(function* () {
      const response = yield* OAuth2TokenResponse.Helper.parseRecord(input);

      if ("error" in response) {
        return yield* OAuth2TokenResponse.Helper.parseErrorResponse(response);
      }

      return yield* OAuth2TokenResponse.Helper.parseSuccessResponse(response);
    });
  }
}

export namespace OAuth2TokenResponse {
  export type Success = {
    type: "success";
    accessToken: string;
    tokenType: "Bearer";
    expiresIn?: typeof ExpiresInSchema.Type;
    refreshToken?: string;
    scope?: OAuth2Scope.Set;
  };

  export type Error = {
    type: "error";
    error: string;
    errorDescription?: string;
    errorUri?: URL;
  };

  export type Value = Success | Error;
}
