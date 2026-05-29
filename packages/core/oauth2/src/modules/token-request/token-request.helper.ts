import { Effect, Schema } from "effect";

import { OAuth2TokenRequestValidationError } from "./token-request.errors";
import { TokenRequestReservedParameterSchema } from "./token-request.schema";

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

  static parseUrl(value: string, message: "Invalid token endpoint") {
    return Effect.mapError(
      Schema.decodeUnknown(Schema.URL)(value),
      () => new OAuth2TokenRequestValidationError({ message }),
    );
  }

  static validateNonEmpty(
    value: string,
    message:
      | "Invalid authorization code"
      | "Invalid refresh token"
      | "Invalid PKCE code verifier",
  ) {
    return Effect.mapError(
      Schema.decodeUnknown(Schema.NonEmptyString)(value),
      () => new OAuth2TokenRequestValidationError({ message }),
    );
  }

  static validateExtensionParameter(parameter: string) {
    if (!Helper.isReservedParameter(parameter)) return Effect.void;

    return Effect.fail(
      new OAuth2TokenRequestValidationError({
        message: "Invalid token request parameter",
        parameter,
      }),
    );
  }

  static isReservedParameter(value: string) {
    return Schema.is(TokenRequestReservedParameterSchema)(value);
  }
}
