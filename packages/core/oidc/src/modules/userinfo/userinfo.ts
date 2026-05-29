import { Effect, Schema } from "effect";

import { OIDCUserInfoValidationError } from "./userinfo.errors";

/**
 * Parses OpenID Connect UserInfo responses.
 */
export class OIDCUserInfo {
  /**
   * Error returned when a UserInfo response is invalid.
   */
  static ValidationError = OIDCUserInfoValidationError;

  /**
   * Parses a UserInfo JSON response and validates its required sub claim.
   */
  static parse(input: unknown) {
    return Effect.gen(function* () {
      const response = yield* OIDCUserInfo.parseRecord(input);
      const sub = yield* Effect.mapError(
        Schema.decodeUnknown(Schema.NonEmptyString)(response.sub),
        () =>
          new OIDCUserInfoValidationError({
            message: "Invalid UserInfo subject",
          }),
      );

      return { ...response, sub };
    });
  }

  private static parseRecord(input: unknown) {
    return Effect.gen(function* () {
      if (typeof input !== "object" || input === null || Array.isArray(input)) {
        return yield* Effect.fail(
          new OIDCUserInfoValidationError({
            message: "Invalid UserInfo response",
          }),
        );
      }

      return input as Readonly<Record<string, unknown>>;
    });
  }
}
