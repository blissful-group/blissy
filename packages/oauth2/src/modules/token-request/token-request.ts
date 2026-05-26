import { Effect, Schema } from "effect";

import { OAuth2Scope } from "../scope/scope";
import { OAuth2TokenRequestValidationError } from "./token-request.errors";
import { TokenRequestReservedParameterSchema } from "./token-request.schema";
import type {
  OAuth2TokenRequestAuthentication,
  OAuth2TokenRequestExtensionParameters,
  OAuth2TokenRequestValue,
} from "./token-request.types";

/**
 * Builds OAuth 2.0 token endpoint request objects without performing IO.
 */
export class OAuth2TokenRequest {
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
    authentication?: OAuth2TokenRequestAuthentication;
    parameters?: OAuth2TokenRequestExtensionParameters;
  }) {
    return Effect.gen(function* () {
      yield* OAuth2TokenRequest.validateNonEmpty(
        code,
        "Invalid authorization code",
      );

      if (codeVerifier !== undefined) {
        yield* OAuth2TokenRequest.validateNonEmpty(
          codeVerifier,
          "Invalid PKCE code verifier",
        );
      }

      if (redirectUri !== undefined) {
        yield* OAuth2TokenRequest.parseUrl(
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
    authentication?: OAuth2TokenRequestAuthentication;
    parameters?: OAuth2TokenRequestExtensionParameters;
  }) {
    return Effect.gen(function* () {
      yield* OAuth2TokenRequest.validateNonEmpty(
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
    authentication?: OAuth2TokenRequestAuthentication;
    parameters?: OAuth2TokenRequestExtensionParameters;
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
    authentication?: OAuth2TokenRequestAuthentication;
    parameters?: OAuth2TokenRequestExtensionParameters;
  }) {
    return Effect.gen(function* () {
      const url = yield* OAuth2TokenRequest.parseUrl(
        tokenEndpoint,
        "Invalid token endpoint",
      );
      const body = new URLSearchParams();

      OAuth2TokenRequest.append(body, bodyParameters);
      OAuth2TokenRequest.append(body, authentication?.bodyParameters ?? {});

      for (const [parameter, value] of Object.entries(parameters ?? {})) {
        if (OAuth2TokenRequest.isReservedParameter(parameter)) {
          const error = new OAuth2TokenRequestValidationError({
            message: "Invalid token request parameter",
            parameter,
          });

          return yield* Effect.fail(error);
        }

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

  private static append(
    body: URLSearchParams,
    parameters: Readonly<Record<string, string | undefined>>,
  ) {
    for (const [parameter, value] of Object.entries(parameters)) {
      if (value !== undefined) {
        body.set(parameter, value);
      }
    }
  }

  private static parseUrl(value: string, message: "Invalid token endpoint") {
    return Effect.mapError(
      Schema.decodeUnknown(Schema.URL)(value),
      () => new OAuth2TokenRequestValidationError({ message }),
    );
  }

  private static validateNonEmpty(
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

  private static isReservedParameter(value: string) {
    return Schema.is(TokenRequestReservedParameterSchema)(value);
  }
}

export namespace OAuth2TokenRequest {
  export type Authentication = OAuth2TokenRequestAuthentication;
  export type ExtensionParameters = OAuth2TokenRequestExtensionParameters;
  export type Request = OAuth2TokenRequestValue;
}
