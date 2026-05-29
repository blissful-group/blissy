import { Effect } from "effect";

import { OAuth2TokenResponseValidationError } from "./token-response.errors";
import { Helper } from "./token-response.helper";
import type {
  OAuth2TokenErrorResponse,
  OAuth2TokenResponseValue,
  OAuth2TokenSuccessResponse,
} from "./token-response.types";

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
  export type Value = OAuth2TokenResponseValue;
  export type Success = OAuth2TokenSuccessResponse;
  export type Error = OAuth2TokenErrorResponse;
}
