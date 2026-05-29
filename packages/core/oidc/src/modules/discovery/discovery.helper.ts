import { Effect, Schema } from "effect";

import { OIDCDiscoveryValidationError } from "./discovery.errors";

export class Helper {
  static issuer(metadata: Readonly<Record<string, unknown>>) {
    return Helper.parseUrlString(metadata.issuer, "Invalid issuer");
  }

  static authorizationEndpoint(metadata: Readonly<Record<string, unknown>>) {
    return Helper.parseUrlString(
      metadata.authorization_endpoint,
      "Invalid authorization endpoint",
    );
  }

  static tokenEndpoint(metadata: Readonly<Record<string, unknown>>) {
    if (metadata.token_endpoint === undefined) return Effect.succeed(undefined);

    return Helper.parseUrlString(
      metadata.token_endpoint,
      "Invalid token endpoint",
    );
  }

  static userinfoEndpoint(metadata: Readonly<Record<string, unknown>>) {
    if (metadata.userinfo_endpoint === undefined)
      return Effect.succeed(undefined);

    return Helper.parseUrlString(
      metadata.userinfo_endpoint,
      "Invalid userinfo endpoint",
    );
  }

  static jwksUri(metadata: Readonly<Record<string, unknown>>) {
    return Helper.parseUrlString(metadata.jwks_uri, "Invalid jwks uri");
  }

  static responseTypes(metadata: Readonly<Record<string, unknown>>) {
    return Helper.parseStringArray(
      metadata.response_types_supported,
      "Invalid response types supported",
    );
  }

  static subjectTypes(metadata: Readonly<Record<string, unknown>>) {
    return Helper.parseStringArray(
      metadata.subject_types_supported,
      "Invalid subject types supported",
    );
  }

  static idTokenAlgs(metadata: Readonly<Record<string, unknown>>) {
    return Helper.parseStringArray(
      metadata.id_token_signing_alg_values_supported,
      "Invalid id token signing alg values supported",
    );
  }

  static scopes(metadata: Readonly<Record<string, unknown>>) {
    if (metadata.scopes_supported === undefined)
      return Effect.succeed(undefined);

    return Helper.parseStringArray(
      metadata.scopes_supported,
      "Invalid scopes supported",
    );
  }

  static claims(metadata: Readonly<Record<string, unknown>>) {
    if (metadata.claims_supported === undefined)
      return Effect.succeed(undefined);

    return Helper.parseStringArray(
      metadata.claims_supported,
      "Invalid claims supported",
    );
  }

  static grantTypes(metadata: Readonly<Record<string, unknown>>) {
    if (metadata.grant_types_supported === undefined) {
      return Effect.succeed(undefined);
    }

    return Helper.parseStringArray(
      metadata.grant_types_supported,
      "Invalid grant types supported",
    );
  }

  static tokenMethods(metadata: Readonly<Record<string, unknown>>) {
    if (metadata.token_endpoint_auth_methods_supported === undefined) {
      return Effect.succeed(undefined);
    }

    return Helper.parseStringArray(
      metadata.token_endpoint_auth_methods_supported,
      "Invalid token endpoint auth methods supported",
    );
  }

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
        new OIDCDiscoveryValidationError({
          message: "Invalid provider metadata",
        }),
      );
    });
  }

  static parseUrlString(
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

  static parseUrl(input: unknown, message: "Invalid issuer") {
    return Effect.mapError(
      Schema.decodeUnknown(Schema.URL)(input),
      () => new OIDCDiscoveryValidationError({ message }),
    );
  }

  static parseStringArray(
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
        if (typeof item === "string" && item !== "") continue;

        return yield* Effect.fail(
          new OIDCDiscoveryValidationError({ message }),
        );
      }

      return input as ReadonlyArray<string>;
    });
  }
}
