import type { OAuth2PKCE } from "@blissy-auth/oauth2";
import { OAuth2AuthorizationRequest, OAuth2Scope } from "@blissy-auth/oauth2";
import { Effect } from "effect";

import { OIDCAuthorizationRequestValidationError } from "./authorization-request.errors";

/**
 * Builds OpenID Connect authorization endpoint request URLs.
 */
export class OIDCAuthorizationRequest {
  /**
   * Error returned when an OIDC authorization request input is invalid.
   */
  static ValidationError = OIDCAuthorizationRequestValidationError;

  /**
   * Builds an Authorization Code request URL with the required openid scope.
   */
  static authorizationCode({
    authorizationEndpoint,
    clientId,
    codeChallenge,
    codeChallengeMethod,
    nonce,
    parameters,
    redirectUri,
    scope = [],
    state,
  }: {
    authorizationEndpoint: string;
    clientId: string;
    redirectUri: string;
    scope?: OAuth2Scope.Set;
    state?: string;
    nonce?: string;
    codeChallenge?: string;
    codeChallengeMethod?: OAuth2PKCE.CodeChallengeMethod;
    parameters?: Readonly<Record<string, string>>;
  }): Effect.Effect<URL, unknown> {
    return Effect.gen(function* () {
      if (parameters?.nonce !== undefined) {
        return yield* Effect.fail(
          new OIDCAuthorizationRequestValidationError({
            message: "Invalid OIDC authorization request parameter",
            parameter: "nonce",
          }),
        );
      }

      const hasOpenId = yield* OAuth2Scope.includes(scope, "openid");
      const oidcScope = hasOpenId ? scope : (["openid", ...scope] as const);

      return yield* OAuth2AuthorizationRequest.authorizationCode({
        authorizationEndpoint,
        clientId,
        codeChallenge,
        codeChallengeMethod,
        parameters: {
          ...parameters,
          ...(nonce === undefined ? {} : { nonce }),
        },
        redirectUri,
        scope: oidcScope,
        state,
      });
    });
  }
}
