import { Effect } from "effect";

import { OIDCDiscoveryValidationError } from "./discovery.errors";
import { Helper } from "./discovery.helper";

/**
 * Parses OpenID Connect provider discovery metadata.
 */
export class OIDCDiscovery {
  private static Helper = Helper;

  /**
   * Error returned when provider metadata is invalid.
   */
  static ValidationError = OIDCDiscoveryValidationError;

  /**
   * Builds the standard OpenID Provider Configuration discovery URL.
   */
  static configurationUrl(issuer: string) {
    return Effect.gen(function* () {
      const url = yield* OIDCDiscovery.Helper.parseUrl(
        issuer,
        "Invalid issuer",
      );

      url.pathname = `${url.pathname.replace(/\/$/u, "")}/.well-known/openid-configuration`;
      url.search = "";
      url.hash = "";

      return url;
    });
  }

  /**
   * Parses an OpenID Provider Metadata document.
   */
  static parse(input: unknown) {
    return Effect.gen(function* () {
      const metadata = yield* OIDCDiscovery.Helper.parseRecord(input);

      return {
        authorizationEndpoint: yield* Helper.authorizationEndpoint(metadata),
        claimsSupported: yield* Helper.claims(metadata),
        grantTypesSupported: yield* Helper.grantTypes(metadata),
        idTokenSigningAlgValuesSupported: yield* Helper.idTokenAlgs(metadata),
        issuer: yield* Helper.issuer(metadata),
        jwksUri: yield* Helper.jwksUri(metadata),
        responseTypesSupported: yield* Helper.responseTypes(metadata),
        scopesSupported: yield* Helper.scopes(metadata),
        subjectTypesSupported: yield* Helper.subjectTypes(metadata),
        tokenEndpoint: yield* Helper.tokenEndpoint(metadata),
        tokenEndpointAuthMethodsSupported: yield* Helper.tokenMethods(metadata),
        userinfoEndpoint: yield* Helper.userinfoEndpoint(metadata),
      };
    });
  }
}
