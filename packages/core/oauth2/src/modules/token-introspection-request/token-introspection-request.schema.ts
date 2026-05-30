import { Schema } from "effect";

export const TokenIntrospectionRequestReservedParameterSchema = Schema.Literal(
  "client_id",
  "client_secret",
  "token",
  "token_type_hint",
);

export const TokenTypeHintSchema = Schema.Literal(
  "access_token",
  "refresh_token",
);
