import { Effect, Schema } from "effect";

import { OAuth2TokenRevocationRequestValidationError } from "./token-revocation-request.errors";
import {
  TokenRevocationRequestReservedParameterSchema,
  TokenTypeHintSchema,
} from "./token-revocation-request.schema";

export class Helper {
  static append(
    body: URLSearchParams,
    parameters: Readonly<Record<string, string | undefined>>,
  ) {
    for (const [parameter, value] of Object.entries(parameters)) {
      if (value !== undefined) {
        body.set(parameter, value);
      }
    }
  }

  static parseUrl(value: string) {
    return Effect.mapError(
      Schema.decodeUnknown(Schema.URL)(value),
      () =>
        new OAuth2TokenRevocationRequestValidationError({
          message: "Invalid revocation endpoint",
        }),
    );
  }

  static validateNonEmpty(value: string) {
    return Effect.mapError(
      Schema.decodeUnknown(Schema.NonEmptyString)(value),
      () =>
        new OAuth2TokenRevocationRequestValidationError({
          message: "Invalid token",
        }),
    );
  }

  static validateTokenTypeHint(value: string) {
    return Effect.mapError(
      Schema.decodeUnknown(TokenTypeHintSchema)(value),
      () =>
        new OAuth2TokenRevocationRequestValidationError({
          message: "Invalid token type hint",
        }),
    );
  }

  static validateExtensionParameter(parameter: string) {
    if (!Helper.isReservedParameter(parameter)) return Effect.void;

    return Effect.fail(
      new OAuth2TokenRevocationRequestValidationError({
        message: "Invalid token revocation request parameter",
        parameter,
      }),
    );
  }

  static isReservedParameter(value: string) {
    return Schema.is(TokenRevocationRequestReservedParameterSchema)(value);
  }
}
