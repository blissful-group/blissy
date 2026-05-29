import { Effect, Schema } from "effect";

import { OAuth2PKCE } from "../pkce/pkce";
import { OAuth2Scope } from "../scope/scope";
import { AuthorizationRequestValidationError } from "./authorization-request.errors";
import { AuthorizationRequestReservedParameterSchema } from "./authorization-request.schema";

/**
 * Builds OAuth 2.0 authorization endpoint request URLs.
 */
export class OAuth2AuthorizationRequest {
  /**
   * Error returned when an authorization request input is invalid.
   */
  static ValidationError = AuthorizationRequestValidationError;

  /**
   * Builds an authorization code request URL.
   */
  static authorizationCode({
    authorizationEndpoint,
    clientId,
    codeChallenge,
    codeChallengeMethod,
    parameters,
    redirectUri,
    scope,
    state,
  }: {
    authorizationEndpoint: string;
    clientId: string;
    redirectUri: string;
    scope?: OAuth2Scope.Set;
    state?: string;
    codeChallenge?: string;
    codeChallengeMethod?: OAuth2PKCE.CodeChallengeMethod;
    parameters?: Readonly<Record<string, string>>;
  }) {
    return Effect.gen(function* () {
      const url = yield* OAuth2AuthorizationRequest.parseUrl(
        authorizationEndpoint,
        "Invalid authorization endpoint",
      );

      yield* OAuth2AuthorizationRequest.validateNonEmpty(
        clientId,
        "Invalid client id",
      );

      yield* OAuth2AuthorizationRequest.parseUrl(
        redirectUri,
        "Invalid redirect uri",
      );

      url.searchParams.set("response_type", "code");
      url.searchParams.set("client_id", clientId);
      url.searchParams.set("redirect_uri", redirectUri);

      if (scope !== undefined) {
        url.searchParams.set("scope", yield* OAuth2Scope.format(scope));
      }

      if (state !== undefined) {
        url.searchParams.set("state", state);
      }

      if (codeChallenge !== undefined) {
        url.searchParams.set("code_challenge", codeChallenge);
      }

      if (codeChallengeMethod !== undefined) {
        yield* OAuth2PKCE.createCodeChallenge({
          codeVerifier: "a".repeat(43),
          method: codeChallengeMethod,
        });
        url.searchParams.set("code_challenge_method", codeChallengeMethod);
      }

      for (const [parameter, value] of Object.entries(parameters ?? {})) {
        if (OAuth2AuthorizationRequest.isReservedParameter(parameter)) {
          const error = new AuthorizationRequestValidationError({
            message: "Invalid authorization request parameter",
            parameter,
          });

          return yield* Effect.fail(error);
        }

        url.searchParams.set(parameter, value);
      }

      return url;
    });
  }

  private static parseUrl(
    value: string,
    message: "Invalid authorization endpoint" | "Invalid redirect uri",
  ) {
    return Effect.mapError(
      Schema.decodeUnknown(Schema.URL)(value),
      () => new AuthorizationRequestValidationError({ message }),
    );
  }

  private static validateNonEmpty(value: string, message: "Invalid client id") {
    return Effect.mapError(
      Schema.decodeUnknown(Schema.NonEmptyString)(value),
      () => new AuthorizationRequestValidationError({ message }),
    );
  }

  private static isReservedParameter(value: string) {
    return Schema.is(AuthorizationRequestReservedParameterSchema)(value);
  }
}
