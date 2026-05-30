import { Effect } from "effect";

import { OAuth2Scope } from "../scope/scope";
import { OAuth2TokenRequestValidationError } from "./token-request.errors";
import { Helper } from "./token-request.helper";

/**
 * Builds OAuth 2.0 token endpoint request objects without performing IO.
 */
export class OAuth2TokenRequest {
  private static Helper = Helper;

  /**
   * Error returned when token request input is invalid.
   */
  static ValidationError = OAuth2TokenRequestValidationError;

  /**
   * Builds an authorization_code token request.
   */
  static authorizationCode({
    authentication,
    code,
    codeVerifier,
    parameters,
    redirectUri,
    tokenEndpoint,
  }: {
    tokenEndpoint: string;
    code: string;
    redirectUri?: string;
    codeVerifier?: string;
    authentication?: OAuth2TokenRequest.Authentication;
    parameters?: OAuth2TokenRequest.ExtensionParameters;
  }) {
    return Effect.gen(function* () {
      yield* OAuth2TokenRequest.Helper.validateNonEmpty(
        code,
        "Invalid authorization code",
      );

      if (codeVerifier !== undefined) {
        yield* OAuth2TokenRequest.Helper.validateNonEmpty(
          codeVerifier,
          "Invalid PKCE code verifier",
        );
      }

      if (redirectUri !== undefined) {
        yield* OAuth2TokenRequest.Helper.parseUrl(
          redirectUri,
          "Invalid token endpoint",
        );
      }

      return yield* OAuth2TokenRequest.build({
        authentication,
        parameters,
        tokenEndpoint,
        bodyParameters: {
          code,
          code_verifier: codeVerifier,
          grant_type: "authorization_code",
          redirect_uri: redirectUri,
        },
      });
    });
  }

  /**
   * Builds a refresh_token token request.
   */
  static refreshToken({
    authentication,
    parameters,
    refreshToken,
    scope,
    tokenEndpoint,
  }: {
    tokenEndpoint: string;
    refreshToken: string;
    scope?: OAuth2Scope.Set;
    authentication?: OAuth2TokenRequest.Authentication;
    parameters?: OAuth2TokenRequest.ExtensionParameters;
  }) {
    return Effect.gen(function* () {
      yield* OAuth2TokenRequest.Helper.validateNonEmpty(
        refreshToken,
        "Invalid refresh token",
      );

      return yield* OAuth2TokenRequest.build({
        authentication,
        parameters,
        tokenEndpoint,
        bodyParameters: {
          grant_type: "refresh_token",
          refresh_token: refreshToken,
          scope:
            scope === undefined ? undefined : yield* OAuth2Scope.format(scope),
        },
      });
    });
  }

  /**
   * Builds a client_credentials token request.
   */
  static clientCredentials({
    authentication,
    parameters,
    scope,
    tokenEndpoint,
  }: {
    tokenEndpoint: string;
    scope?: OAuth2Scope.Set;
    authentication?: OAuth2TokenRequest.Authentication;
    parameters?: OAuth2TokenRequest.ExtensionParameters;
  }) {
    return Effect.gen(function* () {
      return yield* OAuth2TokenRequest.build({
        authentication,
        parameters,
        tokenEndpoint,
        bodyParameters: {
          grant_type: "client_credentials",
          scope:
            scope === undefined ? undefined : yield* OAuth2Scope.format(scope),
        },
      });
    });
  }

  private static build({
    authentication,
    bodyParameters,
    parameters,
    tokenEndpoint,
  }: {
    tokenEndpoint: string;
    bodyParameters: Readonly<Record<string, string | undefined>>;
    authentication?: OAuth2TokenRequest.Authentication;
    parameters?: OAuth2TokenRequest.ExtensionParameters;
  }) {
    return Effect.gen(function* () {
      const url = yield* OAuth2TokenRequest.Helper.parseUrl(
        tokenEndpoint,
        "Invalid token endpoint",
      );
      const body = new URLSearchParams();

      OAuth2TokenRequest.Helper.append(body, bodyParameters);
      OAuth2TokenRequest.Helper.append(
        body,
        authentication?.bodyParameters ?? {},
      );

      for (const [parameter, value] of Object.entries(parameters ?? {})) {
        yield* OAuth2TokenRequest.Helper.validateExtensionParameter(parameter);

        if (value !== undefined && value !== null) {
          body.set(parameter, value);
        }
      }

      return {
        body,
        headers: {
          "Content-Type": "application/x-www-form-urlencoded",
          ...(authentication?.headers ?? {}),
        },
        method: "POST" as const,
        url,
      };
    });
  }
}

export namespace OAuth2TokenRequest {
  export type Authentication = {
    bodyParameters: Readonly<Record<string, string>>;
    headers: Readonly<Record<string, string>>;
  };

  export type ExtensionParameters = Readonly<
    Record<string, string | null | undefined>
  >;

  export type Request = {
    method: "POST";
    url: URL;
    headers: Record<string, string>;
    body: URLSearchParams;
  };
}
