import { Effect, Schema } from "effect";

import { OAuth2ClientAuthenticationError } from "./client-authentication.errors";
import { ClientCredentialSchema } from "./client-authentication.schema";

export class Helper {
  static validateClientId(clientId: string) {
    return Effect.mapError(
      Schema.decodeUnknown(ClientCredentialSchema)(clientId),
      () =>
        new OAuth2ClientAuthenticationError({
          message: "Invalid OAuth2 client id",
        }),
    );
  }

  static validateClientSecret(clientSecret: string) {
    return Effect.mapError(
      Schema.decodeUnknown(ClientCredentialSchema)(clientSecret),
      () =>
        new OAuth2ClientAuthenticationError({
          message: "Invalid OAuth2 client secret",
        }),
    );
  }

  static formEncode(value: string) {
    const parameters = new URLSearchParams({ value });

    return parameters.toString().slice("value=".length);
  }
}
