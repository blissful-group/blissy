import { Effect, Schema } from "effect";

import { OAuth2Scope } from "../scope/scope";
import { OAuth2TokenIntrospectionResponseValidationError } from "./token-introspection-response.errors";
import {
  IntrospectionStringListClaimSchema,
  IntrospectionTimestampClaimSchema,
} from "./token-introspection-response.schema";

export class Helper {
  static active(response: Readonly<Record<string, unknown>>) {
    return Helper.parseActive(response.active);
  }

  static aud(response: Readonly<Record<string, unknown>>) {
    if (response.aud === undefined) return Effect.succeed(undefined);

    return Helper.parseStringListClaim(response.aud, "aud");
  }

  static clientId(response: Readonly<Record<string, unknown>>) {
    if (response.client_id === undefined) return Effect.succeed(undefined);

    return Helper.parseStringClaim(response.client_id, "client_id");
  }

  static exp(response: Readonly<Record<string, unknown>>) {
    if (response.exp === undefined) return Effect.succeed(undefined);

    return Helper.parseTimestampClaim(response.exp, "exp");
  }

  static iat(response: Readonly<Record<string, unknown>>) {
    if (response.iat === undefined) return Effect.succeed(undefined);

    return Helper.parseTimestampClaim(response.iat, "iat");
  }

  static iss(response: Readonly<Record<string, unknown>>) {
    if (response.iss === undefined) return Effect.succeed(undefined);

    return Helper.parseStringClaim(response.iss, "iss");
  }

  static jti(response: Readonly<Record<string, unknown>>) {
    if (response.jti === undefined) return Effect.succeed(undefined);

    return Helper.parseStringClaim(response.jti, "jti");
  }

  static nbf(response: Readonly<Record<string, unknown>>) {
    if (response.nbf === undefined) return Effect.succeed(undefined);

    return Helper.parseTimestampClaim(response.nbf, "nbf");
  }

  static scope(response: Readonly<Record<string, unknown>>) {
    if (response.scope === undefined) return Effect.succeed(undefined);

    return Helper.parseScope(response.scope);
  }

  static sub(response: Readonly<Record<string, unknown>>) {
    if (response.sub === undefined) return Effect.succeed(undefined);

    return Helper.parseStringClaim(response.sub, "sub");
  }

  static tokenType(response: Readonly<Record<string, unknown>>) {
    if (response.token_type === undefined) return Effect.succeed(undefined);

    return Helper.parseTokenType(response.token_type);
  }

  static username(response: Readonly<Record<string, unknown>>) {
    if (response.username === undefined) return Effect.succeed(undefined);

    return Helper.parseStringClaim(response.username, "username");
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
        new OAuth2TokenIntrospectionResponseValidationError({
          message: "Invalid token introspection response",
        }),
      );
    });
  }

  static parseActive(input: unknown) {
    return Effect.mapError(
      Schema.decodeUnknown(Schema.Boolean)(input),
      () =>
        new OAuth2TokenIntrospectionResponseValidationError({
          message: "Invalid active flag",
        }),
    );
  }

  static parseScope(input: unknown) {
    return Effect.gen(function* () {
      const scope = yield* Helper.parseStringClaim(input, "scope");

      return yield* Effect.mapError(
        OAuth2Scope.parse(scope),
        () =>
          new OAuth2TokenIntrospectionResponseValidationError({
            claim: "scope",
            message: "Invalid token scope",
          }),
      );
    });
  }

  static parseTokenType(input: unknown) {
    return Effect.mapError(
      Schema.decodeUnknown(Schema.NonEmptyString)(input),
      () =>
        new OAuth2TokenIntrospectionResponseValidationError({
          claim: "token_type",
          message: "Invalid token type",
        }),
    );
  }

  static parseStringClaim(input: unknown, claim: string) {
    return Effect.mapError(
      Schema.decodeUnknown(Schema.NonEmptyString)(input),
      () =>
        new OAuth2TokenIntrospectionResponseValidationError({
          claim,
          message: "Invalid token introspection string claim",
        }),
    );
  }

  static parseStringListClaim(input: unknown, claim: string) {
    return Effect.mapError(
      Schema.decodeUnknown(IntrospectionStringListClaimSchema)(input),
      () =>
        new OAuth2TokenIntrospectionResponseValidationError({
          claim,
          message: "Invalid token introspection string list claim",
        }),
    );
  }

  static parseTimestampClaim(input: unknown, claim: string) {
    return Effect.mapError(
      Schema.decodeUnknown(IntrospectionTimestampClaimSchema)(input),
      () =>
        new OAuth2TokenIntrospectionResponseValidationError({
          claim,
          message: "Invalid token introspection timestamp claim",
        }),
    );
  }
}
