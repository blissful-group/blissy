import { Effect, Schema } from "effect";

import { OIDCDiscoveryValidationError } from "./discovery.errors";

/**
 * Parses OpenID Connect provider discovery metadata.
 */
export class OIDCDiscovery {
  /**
   * Error returned when provider metadata is invalid.
   */
  static ValidationError = OIDCDiscoveryValidationError;

  /**
   * Builds the standard OpenID Provider Configuration discovery URL.
   */
  static configurationUrl(issuer: string) {
    return Effect.gen(function* () {
      const url = yield* OIDCDiscovery.parseUrl(issuer, "Invalid issuer");

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
      const metadata = yield* OIDCDiscovery.parseRecord(input);

      return {
        authorizationEndpoint: yield* OIDCDiscovery.parseUrlString(
          metadata.authorization_endpoint,
          "Invalid authorization endpoint",
        ),
        claimsSupported:
          metadata.claims_supported === undefined
            ? undefined
            : yield* OIDCDiscovery.parseStringArray(
                metadata.claims_supported,
                "Invalid claims supported",
              ),
        grantTypesSupported:
          metadata.grant_types_supported === undefined
            ? undefined
            : yield* OIDCDiscovery.parseStringArray(
                metadata.grant_types_supported,
                "Invalid grant types supported",
              ),
        idTokenSigningAlgValuesSupported: yield* OIDCDiscovery.parseStringArray(
          metadata.id_token_signing_alg_values_supported,
          "Invalid id token signing alg values supported",
        ),
        issuer: yield* OIDCDiscovery.parseUrlString(
          metadata.issuer,
          "Invalid issuer",
        ),
        jwksUri: yield* OIDCDiscovery.parseUrlString(
          metadata.jwks_uri,
          "Invalid jwks uri",
        ),
        responseTypesSupported: yield* OIDCDiscovery.parseStringArray(
          metadata.response_types_supported,
          "Invalid response types supported",
        ),
        scopesSupported:
          metadata.scopes_supported === undefined
            ? undefined
            : yield* OIDCDiscovery.parseStringArray(
                metadata.scopes_supported,
                "Invalid scopes supported",
              ),
        subjectTypesSupported: yield* OIDCDiscovery.parseStringArray(
          metadata.subject_types_supported,
          "Invalid subject types supported",
        ),
        tokenEndpoint:
          metadata.token_endpoint === undefined
            ? undefined
            : yield* OIDCDiscovery.parseUrlString(
                metadata.token_endpoint,
                "Invalid token endpoint",
              ),
        tokenEndpointAuthMethodsSupported:
          metadata.token_endpoint_auth_methods_supported === undefined
            ? undefined
            : yield* OIDCDiscovery.parseStringArray(
                metadata.token_endpoint_auth_methods_supported,
                "Invalid token endpoint auth methods supported",
              ),
        userinfoEndpoint:
          metadata.userinfo_endpoint === undefined
            ? undefined
            : yield* OIDCDiscovery.parseUrlString(
                metadata.userinfo_endpoint,
                "Invalid userinfo endpoint",
              ),
      };
    });
  }

  private static parseRecord(input: unknown) {
    return Effect.gen(function* () {
      if (typeof input !== "object" || input === null || Array.isArray(input)) {
        return yield* Effect.fail(
          new OIDCDiscoveryValidationError({
            message: "Invalid provider metadata",
          }),
        );
      }

      return input as Readonly<Record<string, unknown>>;
    });
  }

  private static parseUrlString(
    input: unknown,
    message:
      | "Invalid issuer"
      | "Invalid authorization endpoint"
      | "Invalid token endpoint"
      | "Invalid userinfo endpoint"
      | "Invalid jwks uri",
  ) {
    return Effect.mapError(
      Schema.decodeUnknown(Schema.URL)(input),
      () => new OIDCDiscoveryValidationError({ message }),
    );
  }

  private static parseUrl(input: unknown, message: "Invalid issuer") {
    return Effect.mapError(
      Schema.decodeUnknown(Schema.URL)(input),
      () => new OIDCDiscoveryValidationError({ message }),
    );
  }

  private static parseStringArray(
    input: unknown,
    message:
      | "Invalid response types supported"
      | "Invalid subject types supported"
      | "Invalid id token signing alg values supported"
      | "Invalid scopes supported"
      | "Invalid claims supported"
      | "Invalid grant types supported"
      | "Invalid token endpoint auth methods supported",
  ) {
    return Effect.gen(function* () {
      if (!Array.isArray(input) || input.length === 0) {
        return yield* Effect.fail(
          new OIDCDiscoveryValidationError({ message }),
        );
      }

      for (const item of input) {
        if (typeof item !== "string" || item === "") {
          return yield* Effect.fail(
            new OIDCDiscoveryValidationError({ message }),
          );
        }
      }

      return input as ReadonlyArray<string>;
    });
  }
}
