import { Effect, Schema } from "effect";

import { OAuth2Scope } from "../scope/scope";
import { OAuth2TokenResponseValidationError } from "./token-response.errors";
import {
  ExpiresInSchema,
  TokenErrorFieldSchema,
  TokenErrorUriSchema,
} from "./token-response.schema";

export class Helper {
  static parseSuccessResponse(response: Readonly<Record<string, unknown>>) {
    return Effect.gen(function* () {
      const accessToken = yield* Helper.parseNonEmptyString(
        response.access_token,
        "Invalid access token",
      );
      const tokenType = yield* Helper.parseTokenType(response.token_type);
      const expiresIn =
        response.expires_in === undefined
          ? undefined
          : yield* Helper.parseExpiresIn(response.expires_in);
      const refreshToken =
        response.refresh_token === undefined
          ? undefined
          : yield* Helper.parseNonEmptyString(
              response.refresh_token,
              "Invalid token response",
            );
      const scope =
        response.scope === undefined
          ? undefined
          : yield* OAuth2Scope.parse(
              yield* Helper.parseNonEmptyString(
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

  static parseErrorResponse(response: Readonly<Record<string, unknown>>) {
    return Effect.gen(function* () {
      const error = yield* Helper.parseErrorField(
        response.error,
        "Invalid token error",
      );
      const errorDescription =
        response.error_description === undefined
          ? undefined
          : yield* Helper.parseErrorField(
              response.error_description,
              "Invalid token error",
            );
      const errorUri =
        response.error_uri === undefined
          ? undefined
          : yield* Helper.parseErrorUri(response.error_uri);

      return {
        error,
        errorDescription,
        errorUri,
        type: "error" as const,
      };
    });
  }

  static parseRecord(input: unknown) {
    return Effect.gen(function* () {
      if (
        typeof input === "object" &&
        input !== null &&
        !Array.isArray(input)
      ) {
        return input as Readonly<Record<string, unknown>>;
      }

      return yield* Effect.fail(
        new OAuth2TokenResponseValidationError({
          message: "Invalid token response",
        }),
      );
    });
  }

  static parseTokenType(input: unknown) {
    return Effect.gen(function* () {
      const tokenType = yield* Helper.parseNonEmptyString(
        input,
        "Invalid token type",
      );

      if (tokenType.toLowerCase() === "bearer") return "Bearer" as const;

      return yield* Effect.fail(
        new OAuth2TokenResponseValidationError({
          message: "Invalid token type",
        }),
      );
    });
  }

  static parseExpiresIn(input: unknown) {
    return Effect.mapError(
      Schema.decodeUnknown(ExpiresInSchema)(input),
      () =>
        new OAuth2TokenResponseValidationError({
          message: "Invalid expires_in",
        }),
    );
  }

  static parseErrorField(input: unknown, message: "Invalid token error") {
    return Effect.mapError(
      Schema.decodeUnknown(TokenErrorFieldSchema)(input),
      () => new OAuth2TokenResponseValidationError({ message }),
    );
  }

  static parseErrorUri(input: unknown) {
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

  static parseNonEmptyString(
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
