import { Effect, Schema } from "effect";

import { OAuth2Scope } from "../scope/scope";
import { OAuth2TokenResponseValidationError } from "./token-response.errors";
import {
  ExpiresInSchema,
  TokenErrorFieldSchema,
  TokenErrorUriSchema,
} from "./token-response.schema";
import type {
  OAuth2TokenErrorResponse,
  OAuth2TokenResponseValue,
  OAuth2TokenSuccessResponse,
} from "./token-response.types";

/**
 * Parses OAuth 2.0 token endpoint JSON responses.
 */
export class OAuth2TokenResponse {
  /**
   * Error returned when a token response is invalid.
   */
  static ValidationError = OAuth2TokenResponseValidationError;

  /**
   * Parses either a successful token response or an OAuth token error response.
   */
  static parse(input: unknown) {
    return Effect.gen(function* () {
      const response = yield* OAuth2TokenResponse.parseRecord(input);

      if ("error" in response) {
        return yield* OAuth2TokenResponse.parseErrorResponse(response);
      }

      return yield* OAuth2TokenResponse.parseSuccessResponse(response);
    });
  }

  private static parseSuccessResponse(
    response: Readonly<Record<string, unknown>>,
  ) {
    return Effect.gen(function* () {
      const accessToken = yield* OAuth2TokenResponse.parseNonEmptyString(
        response.access_token,
        "Invalid access token",
      );
      const tokenType = yield* OAuth2TokenResponse.parseTokenType(
        response.token_type,
      );
      const expiresIn =
        response.expires_in === undefined
          ? undefined
          : yield* OAuth2TokenResponse.parseExpiresIn(response.expires_in);
      const refreshToken =
        response.refresh_token === undefined
          ? undefined
          : yield* OAuth2TokenResponse.parseNonEmptyString(
              response.refresh_token,
              "Invalid token response",
            );
      const scope =
        response.scope === undefined
          ? undefined
          : yield* OAuth2Scope.parse(
              yield* OAuth2TokenResponse.parseNonEmptyString(
                response.scope,
                "Invalid token response",
              ),
            );

      return {
        accessToken,
        expiresIn,
        refreshToken,
        scope,
        tokenType,
        type: "success" as const,
      };
    });
  }

  private static parseErrorResponse(
    response: Readonly<Record<string, unknown>>,
  ) {
    return Effect.gen(function* () {
      const error = yield* OAuth2TokenResponse.parseErrorField(
        response.error,
        "Invalid token error",
      );
      const errorDescription =
        response.error_description === undefined
          ? undefined
          : yield* OAuth2TokenResponse.parseErrorField(
              response.error_description,
              "Invalid token error",
            );
      const errorUri =
        response.error_uri === undefined
          ? undefined
          : yield* OAuth2TokenResponse.parseErrorUri(response.error_uri);

      return {
        error,
        errorDescription,
        errorUri,
        type: "error" as const,
      };
    });
  }

  private static parseRecord(input: unknown) {
    return Effect.gen(function* () {
      if (typeof input !== "object" || input === null || Array.isArray(input)) {
        return yield* Effect.fail(
          new OAuth2TokenResponseValidationError({
            message: "Invalid token response",
          }),
        );
      }

      return input as Readonly<Record<string, unknown>>;
    });
  }

  private static parseTokenType(input: unknown) {
    return Effect.gen(function* () {
      const tokenType = yield* OAuth2TokenResponse.parseNonEmptyString(
        input,
        "Invalid token type",
      );

      if (tokenType.toLowerCase() !== "bearer") {
        return yield* Effect.fail(
          new OAuth2TokenResponseValidationError({
            message: "Invalid token type",
          }),
        );
      }

      return "Bearer" as const;
    });
  }

  private static parseExpiresIn(input: unknown) {
    return Effect.mapError(
      Schema.decodeUnknown(ExpiresInSchema)(input),
      () =>
        new OAuth2TokenResponseValidationError({
          message: "Invalid expires_in",
        }),
    );
  }

  private static parseErrorField(
    input: unknown,
    message: "Invalid token error",
  ) {
    return Effect.mapError(
      Schema.decodeUnknown(TokenErrorFieldSchema)(input),
      () => new OAuth2TokenResponseValidationError({ message }),
    );
  }

  private static parseErrorUri(input: unknown) {
    return Effect.gen(function* () {
      const errorUri = yield* Effect.mapError(
        Schema.decodeUnknown(TokenErrorUriSchema)(input),
        () =>
          new OAuth2TokenResponseValidationError({
            message: "Invalid token error URI",
          }),
      );

      return yield* Effect.mapError(
        Schema.decodeUnknown(Schema.URL)(errorUri),
        () =>
          new OAuth2TokenResponseValidationError({
            message: "Invalid token error URI",
          }),
      );
    });
  }

  private static parseNonEmptyString(
    input: unknown,
    message:
      | "Invalid token response"
      | "Invalid access token"
      | "Invalid token type",
  ) {
    return Effect.mapError(
      Schema.decodeUnknown(Schema.NonEmptyString)(input),
      () => new OAuth2TokenResponseValidationError({ message }),
    );
  }
}

export namespace OAuth2TokenResponse {
  export type Value = OAuth2TokenResponseValue;
  export type Success = OAuth2TokenSuccessResponse;
  export type Error = OAuth2TokenErrorResponse;
}
