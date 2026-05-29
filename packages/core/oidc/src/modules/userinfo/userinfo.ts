import { Effect } from "effect";

import { OIDCUserInfoValidationError } from "./userinfo.errors";
import { Helper } from "./userinfo.helper";

/**
 * Parses OpenID Connect UserInfo responses.
 */
export class OIDCUserInfo {
  private static Helper = Helper;

  /**
   * Error returned when a UserInfo response is invalid.
   */
  static ValidationError = OIDCUserInfoValidationError;

  /**
   * Parses a UserInfo JSON response and validates its required sub claim.
   */
  static parse(input: unknown) {
    return Effect.gen(function* () {
      const response = yield* OIDCUserInfo.Helper.parseRecord(input);
      const sub = yield* OIDCUserInfo.Helper.parseSubject(response.sub);

      return { ...response, sub };
    });
  }
}
