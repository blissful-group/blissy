import { Effect, Schema } from "effect";

import { OIDCUserInfoValidationError } from "./userinfo.errors";

export class Helper {
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
        new OIDCUserInfoValidationError({
          message: "Invalid UserInfo response",
        }),
      );
    });
  }

  static parseSubject(input: unknown) {
    return Effect.mapError(
      Schema.decodeUnknown(Schema.NonEmptyString)(input),
      () =>
        new OIDCUserInfoValidationError({
          message: "Invalid UserInfo subject",
        }),
    );
  }
}
