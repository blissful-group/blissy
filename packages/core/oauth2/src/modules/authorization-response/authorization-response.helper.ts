import { Effect, Schema } from "effect";

import { AuthorizationResponseValidationError } from "./authorization-response.errors";
import {
  AuthorizationErrorFieldSchema,
  AuthorizationErrorUriSchema,
  ReservedParameterSchema,
} from "./authorization-response.schema";

export class Helper {
  static parseErrorResponse(url: URL, errorCode: string) {
    return Effect.gen(function* () {
      yield* Helper.validateErrorField(
        errorCode,
        "Invalid authorization error",
      );

      const errorDescription =
        url.searchParams.get("error_description") ?? undefined;

      if (errorDescription !== undefined) {
        yield* Helper.validateErrorField(
          errorDescription,
          "Invalid authorization error description",
        );
      }

      const errorUri = url.searchParams.get("error_uri") ?? undefined;

      if (errorUri !== undefined) {
        yield* Helper.parseErrorUri(errorUri);
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

  static validateNoDuplicateParameters(url: URL) {
    return Effect.gen(function* () {
      const checkedParameters = new Set<string>();

      for (const parameter of url.searchParams.keys()) {
        if (checkedParameters.has(parameter)) continue;

        checkedParameters.add(parameter);

        if (!Helper.isReservedParameter(parameter)) continue;
        if (url.searchParams.getAll(parameter).length <= 1) continue;

        return yield* Effect.fail(
          new AuthorizationResponseValidationError({
            message: "Duplicate authorization response parameter",
            parameter,
          }),
        );
      }
    });
  }

  static isReservedParameter(value: string) {
    return Schema.is(ReservedParameterSchema)(value);
  }

  static validateErrorField(
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

  static parseUrl(callbackUrl: string) {
    return Effect.mapError(
      Schema.decodeUnknown(Schema.URL)(callbackUrl),
      () =>
        new AuthorizationResponseValidationError({
          message: "Invalid authorization callback URL",
        }),
    );
  }

  static parseErrorUri(errorUri: string) {
    return Effect.gen(function* () {
      yield* Effect.mapError(
        Schema.decodeUnknown(AuthorizationErrorUriSchema)(errorUri),
        () =>
          new AuthorizationResponseValidationError({
            message: "Invalid authorization error URI",
          }),
      );

      return yield* Effect.mapError(
        Schema.decodeUnknown(Schema.URL)(errorUri),
        () =>
          new AuthorizationResponseValidationError({
            message: "Invalid authorization error URI",
          }),
      );
    });
  }
}
