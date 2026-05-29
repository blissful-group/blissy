import { OAuth2AuthorizationResponse } from "@blissy-auth/oauth2/source";
import type { Effect } from "effect";

type OIDCAuthorizationCodeCallback =
  | {
      code: string;
      state?: string;
      type: "success";
    }
  | {
      error: string;
      errorDescription?: string;
      errorUri?: string;
      state?: string;
      type: "error";
    };

/**
 * Parses OpenID Connect authorization endpoint callback responses.
 */
export class OIDCCallback {
  /**
   * Parses an Authorization Code callback response.
   */
  static authorizationCode(input: {
    callbackUrl: string;
    expectedState?: string;
  }): Effect.Effect<OIDCAuthorizationCodeCallback, unknown> {
    return OAuth2AuthorizationResponse.parse(input);
  }
}
