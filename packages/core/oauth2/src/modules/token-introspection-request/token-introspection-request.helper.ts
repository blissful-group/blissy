import { Effect, Schema } from "effect";

import { OAuth2TokenIntrospectionRequestValidationError } from "./token-introspection-request.errors";
import {
  TokenIntrospectionRequestReservedParameterSchema,
  TokenTypeHintSchema,
} from "./token-introspection-request.schema";

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
        new OAuth2TokenIntrospectionRequestValidationError({
          message: "Invalid introspection endpoint",
        }),
    );
  }

  static validateNonEmpty(value: string) {
    return Effect.mapError(
      Schema.decodeUnknown(Schema.NonEmptyString)(value),
      () =>
        new OAuth2TokenIntrospectionRequestValidationError({
          message: "Invalid token",
        }),
    );
  }

  static validateTokenTypeHint(value: string) {
    return Effect.mapError(
      Schema.decodeUnknown(TokenTypeHintSchema)(value),
      () =>
        new OAuth2TokenIntrospectionRequestValidationError({
          message: "Invalid token type hint",
        }),
    );
  }

  static validateExtensionParameter(parameter: string) {
    if (!Helper.isReservedParameter(parameter)) return Effect.void;

    return Effect.fail(
      new OAuth2TokenIntrospectionRequestValidationError({
        message: "Invalid token introspection request parameter",
        parameter,
      }),
    );
  }

  static isReservedParameter(value: string) {
    return Schema.is(TokenIntrospectionRequestReservedParameterSchema)(value);
  }
}
