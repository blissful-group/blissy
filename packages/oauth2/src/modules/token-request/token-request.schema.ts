import { Schema } from "effect";

export const TokenRequestReservedParameterSchema = Schema.Literal(
  "client_id",
  "client_secret",
  "code",
  "code_verifier",
  "grant_type",
  "redirect_uri",
  "refresh_token",
  "scope",
);
