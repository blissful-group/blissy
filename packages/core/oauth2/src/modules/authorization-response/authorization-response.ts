import { Effect } from "effect";

import { OAuth2State } from "../state/state";
import { AuthorizationResponseValidationError } from "./authorization-response.errors";
import { Helper } from "./authorization-response.helper";

/**
 * Parses OAuth 2.0 authorization endpoint callback responses.
 */
export class OAuth2AuthorizationResponse {
  private static Helper = Helper;

  /**
   * Error returned when an authorization response is invalid.
   */
  static ValidationError = AuthorizationResponseValidationError;

  /**
   * Parses an authorization response from a callback URL.
   */
  static parse({
    callbackUrl,
    expectedState,
    responseMode = "query",
  }: {
    callbackUrl: string;
    expectedState?: string;
    responseMode?: "query";
  }) {
    return Effect.gen(function* () {
      if (responseMode !== "query") {
        const error = new AuthorizationResponseValidationError({
          message: "Unsupported authorization response mode",
          responseMode,
        });

        return yield* Effect.fail(error);
      }

      const url =
        yield* OAuth2AuthorizationResponse.Helper.parseUrl(callbackUrl);
      yield* OAuth2AuthorizationResponse.Helper.validateNoDuplicateParameters(
        url,
      );

      const code = url.searchParams.get("code");
      const errorCode = url.searchParams.get("error");
      const state = url.searchParams.get("state") ?? undefined;

      if (expectedState !== undefined) {
        yield* OAuth2State.validate({ expectedState, returnedState: state });
      }

      if (code !== null && errorCode !== null) {
        const error = new AuthorizationResponseValidationError({
          message: "Invalid authorization response",
        });

        return yield* Effect.fail(error);
      }

      if (errorCode !== null) {
        return yield* OAuth2AuthorizationResponse.Helper.parseErrorResponse(
          url,
          errorCode,
        );
      }

      if (code === null || code === "") {
        const error = new AuthorizationResponseValidationError({
          message: "Invalid authorization response",
        });

        return yield* Effect.fail(error);
      }

      return {
        code,
        state,
        type: "success" as const,
      };
    });
  }
}
