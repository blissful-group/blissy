import { Effect, Schema } from "effect";

import { AuthorizationRequestValidationError } from "./authorization-request.errors";
import { AuthorizationRequestReservedParameterSchema } from "./authorization-request.schema";

export class Helper {
  static parseUrl(
    value: string,
    message: "Invalid authorization endpoint" | "Invalid redirect uri",
  ) {
    return Effect.mapError(
      Schema.decodeUnknown(Schema.URL)(value),
      () => new AuthorizationRequestValidationError({ message }),
    );
  }

  static validateNonEmpty(value: string, message: "Invalid client id") {
    return Effect.mapError(
      Schema.decodeUnknown(Schema.NonEmptyString)(value),
      () => new AuthorizationRequestValidationError({ message }),
    );
  }

  static validateExtensionParameter(parameter: string) {
    if (!Helper.isReservedParameter(parameter)) return Effect.void;

    return Effect.fail(
      new AuthorizationRequestValidationError({
        message: "Invalid authorization request parameter",
        parameter,
      }),
    );
  }

  static isReservedParameter(value: string) {
    return Schema.is(AuthorizationRequestReservedParameterSchema)(value);
  }
}
