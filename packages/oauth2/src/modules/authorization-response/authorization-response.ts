import { Effect, Schema } from "effect";

import { OAuth2State } from "../state/state";
import { AuthorizationResponseValidationError } from "./authorization-response.errors";
import {
  AuthorizationErrorFieldSchema,
  AuthorizationErrorUriSchema,
  ReservedParameterSchema,
} from "./authorization-response.schema";

/**
 * Parses OAuth 2.0 authorization endpoint callback responses.
 */
export class OAuth2AuthorizationResponse {
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

      const url = yield* OAuth2AuthorizationResponse.parseUrl(callbackUrl);
      yield* OAuth2AuthorizationResponse.validateNoDuplicateParameters(url);

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
        return yield* OAuth2AuthorizationResponse.parseErrorResponse(
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

  private static parseErrorResponse(url: URL, errorCode: string) {
    return Effect.gen(function* () {
      yield* OAuth2AuthorizationResponse.validateErrorField(
        errorCode,
        "Invalid authorization error",
      );

      const errorDescription =
        url.searchParams.get("error_description") ?? undefined;

      if (errorDescription !== undefined) {
        yield* OAuth2AuthorizationResponse.validateErrorField(
          errorDescription,
          "Invalid authorization error description",
        );
      }

      const errorUri = url.searchParams.get("error_uri") ?? undefined;

      if (errorUri !== undefined) {
        yield* OAuth2AuthorizationResponse.parseErrorUri(errorUri);
      }

      return {
        error: errorCode,
        errorDescription,
        errorUri,
        state: url.searchParams.get("state") ?? undefined,
        type: "error" as const,
      };
    });
  }

  private static validateNoDuplicateParameters(url: URL) {
    return Effect.gen(function* () {
      const checkedParameters = new Set<string>();

      for (const parameter of url.searchParams.keys()) {
        if (checkedParameters.has(parameter)) {
          continue;
        }

        checkedParameters.add(parameter);

        if (!OAuth2AuthorizationResponse.isReservedParameter(parameter)) {
          continue;
        }

        if (url.searchParams.getAll(parameter).length > 1) {
          const error = new AuthorizationResponseValidationError({
            message: "Duplicate authorization response parameter",
            parameter,
          });

          return yield* Effect.fail(error);
        }
      }
    });
  }

  private static isReservedParameter(value: string) {
    return Schema.is(ReservedParameterSchema)(value);
  }

  private static validateErrorField(
    value: string,
    message:
      | "Invalid authorization error"
      | "Invalid authorization error description",
  ) {
    return Effect.mapError(
      Schema.decodeUnknown(AuthorizationErrorFieldSchema)(value),
      () => new AuthorizationResponseValidationError({ message }),
    );
  }

  private static parseUrl(callbackUrl: string) {
    return Effect.try({
      try: () => new URL(callbackUrl),
      catch: () => {
        return new AuthorizationResponseValidationError({
          message: "Invalid authorization callback URL",
        });
      },
    });
  }

  private static parseErrorUri(errorUri: string) {
    return Effect.gen(function* () {
      yield* Effect.mapError(
        Schema.decodeUnknown(AuthorizationErrorUriSchema)(errorUri),
        () => {
          return new AuthorizationResponseValidationError({
            message: "Invalid authorization error URI",
          });
        },
      );

      return yield* Effect.try({
        try: () => new URL(errorUri),
        catch: () => {
          return new AuthorizationResponseValidationError({
            message: "Invalid authorization error URI",
          });
        },
      });
    });
  }
}
