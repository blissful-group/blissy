import { Effect } from "effect";

import type { OAuth2TokenRequest } from "../token-request/token-request";
import { OAuth2TokenRevocationRequestValidationError } from "./token-revocation-request.errors";
import { Helper } from "./token-revocation-request.helper";
import type { TokenTypeHintSchema } from "./token-revocation-request.schema";

/**
 * Builds OAuth 2.0 token revocation endpoint request objects without performing IO.
 */
export class OAuth2TokenRevocationRequest {
  private static Helper = Helper;

  /**
   * Error returned when token revocation request input is invalid.
   */
  static ValidationError = OAuth2TokenRevocationRequestValidationError;

  /**
   * Builds a token revocation request.
   */
  static create({
    authentication,
    parameters,
    revocationEndpoint,
    token,
    tokenTypeHint,
  }: {
    revocationEndpoint: string;
    token: string;
    tokenTypeHint?: typeof TokenTypeHintSchema.Type;
    authentication?: OAuth2TokenRevocationRequest.Authentication;
    parameters?: OAuth2TokenRevocationRequest.ExtensionParameters;
  }) {
    return Effect.gen(function* () {
      const url =
        yield* OAuth2TokenRevocationRequest.Helper.parseUrl(revocationEndpoint);

      yield* OAuth2TokenRevocationRequest.Helper.validateNonEmpty(token);

      if (tokenTypeHint !== undefined) {
        yield* OAuth2TokenRevocationRequest.Helper.validateTokenTypeHint(
          tokenTypeHint,
        );
      }

      const body = new URLSearchParams();

      OAuth2TokenRevocationRequest.Helper.append(body, {
        token,
        token_type_hint: tokenTypeHint,
      });
      OAuth2TokenRevocationRequest.Helper.append(
        body,
        authentication?.bodyParameters ?? {},
      );

      for (const [parameter, value] of Object.entries(parameters ?? {})) {
        yield* OAuth2TokenRevocationRequest.Helper.validateExtensionParameter(
          parameter,
        );

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

export namespace OAuth2TokenRevocationRequest {
  export type Authentication = OAuth2TokenRequest.Authentication;

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
