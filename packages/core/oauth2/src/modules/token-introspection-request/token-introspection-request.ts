import { Effect } from "effect";

import type { OAuth2TokenRequest } from "../token-request/token-request";
import { OAuth2TokenIntrospectionRequestValidationError } from "./token-introspection-request.errors";
import { Helper } from "./token-introspection-request.helper";
import type { TokenTypeHintSchema } from "./token-introspection-request.schema";

/**
 * Builds OAuth 2.0 token introspection endpoint request objects without performing IO.
 */
export class OAuth2TokenIntrospectionRequest {
  private static Helper = Helper;

  /**
   * Error returned when token introspection request input is invalid.
   */
  static ValidationError = OAuth2TokenIntrospectionRequestValidationError;

  /**
   * Builds a token introspection request.
   */
  static create({
    authentication,
    introspectionEndpoint,
    parameters,
    token,
    tokenTypeHint,
  }: {
    introspectionEndpoint: string;
    token: string;
    tokenTypeHint?: typeof TokenTypeHintSchema.Type;
    authentication?: OAuth2TokenIntrospectionRequest.Authentication;
    parameters?: OAuth2TokenIntrospectionRequest.ExtensionParameters;
  }) {
    return Effect.gen(function* () {
      const url = yield* OAuth2TokenIntrospectionRequest.Helper.parseUrl(
        introspectionEndpoint,
      );

      yield* OAuth2TokenIntrospectionRequest.Helper.validateNonEmpty(token);

      if (tokenTypeHint !== undefined) {
        yield* OAuth2TokenIntrospectionRequest.Helper.validateTokenTypeHint(
          tokenTypeHint,
        );
      }

      const body = new URLSearchParams();

      OAuth2TokenIntrospectionRequest.Helper.append(body, {
        token,
        token_type_hint: tokenTypeHint,
      });
      OAuth2TokenIntrospectionRequest.Helper.append(
        body,
        authentication?.bodyParameters ?? {},
      );

      for (const [parameter, value] of Object.entries(parameters ?? {})) {
        yield* OAuth2TokenIntrospectionRequest.Helper.validateExtensionParameter(
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

export namespace OAuth2TokenIntrospectionRequest {
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
