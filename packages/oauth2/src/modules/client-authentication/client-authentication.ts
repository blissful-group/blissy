import { Effect, Schema } from "effect";

import { OAuth2ClientAuthenticationError } from "./client-authentication.errors";
import { ClientCredentialSchema } from "./client-authentication.schema";

/**
 * Builds reusable OAuth 2.0 client authentication request fragments.
 */
export class OAuth2ClientAuthentication {
  /**
   * Error returned when client authentication input is invalid.
   */
  static Error = OAuth2ClientAuthenticationError;

  /**
   * Builds public client authentication with no client secret.
   */
  static none({
    clientId,
    clientSecret,
    includeClientId = false,
    strict = false,
  }: {
    clientId: string;
    clientSecret?: string;
    includeClientId?: boolean;
    strict?: boolean;
  }) {
    return Effect.gen(function* () {
      yield* OAuth2ClientAuthentication.validateClientId(clientId);

      if (strict && clientSecret !== undefined) {
        const error = new OAuth2ClientAuthenticationError({
          message: "Invalid OAuth2 client authentication",
        });

        return yield* Effect.fail(error);
      }

      return {
        bodyParameters: includeClientId ? { client_id: clientId } : {},
        headers: {},
      };
    });
  }

  /**
   * Builds client_secret_basic authentication.
   */
  static clientSecretBasic({
    clientId,
    clientSecret,
  }: {
    clientId: string;
    clientSecret: string;
  }) {
    return Effect.gen(function* () {
      yield* OAuth2ClientAuthentication.validateClientId(clientId);
      yield* OAuth2ClientAuthentication.validateClientSecret(clientSecret);

      const encodedCredentials = btoa(
        `${OAuth2ClientAuthentication.formEncode(clientId)}:${OAuth2ClientAuthentication.formEncode(clientSecret)}`,
      );

      return {
        bodyParameters: {},
        headers: {
          Authorization: `Basic ${encodedCredentials}`,
        },
      };
    });
  }

  /**
   * Builds client_secret_post authentication.
   */
  static clientSecretPost({
    clientId,
    clientSecret,
  }: {
    clientId: string;
    clientSecret: string;
  }) {
    return Effect.gen(function* () {
      yield* OAuth2ClientAuthentication.validateClientId(clientId);
      yield* OAuth2ClientAuthentication.validateClientSecret(clientSecret);

      return {
        bodyParameters: {
          client_id: clientId,
          client_secret: clientSecret,
        },
        headers: {},
      };
    });
  }

  private static validateClientId(clientId: string) {
    return Effect.mapError(
      Schema.decodeUnknown(ClientCredentialSchema)(clientId),
      () =>
        new OAuth2ClientAuthenticationError({
          message: "Invalid OAuth2 client id",
        }),
    );
  }

  private static validateClientSecret(clientSecret: string) {
    return Effect.mapError(
      Schema.decodeUnknown(ClientCredentialSchema)(clientSecret),
      () =>
        new OAuth2ClientAuthenticationError({
          message: "Invalid OAuth2 client secret",
        }),
    );
  }

  private static formEncode(value: string) {
    const parameters = new URLSearchParams({ value });

    return parameters.toString().slice("value=".length);
  }
}
