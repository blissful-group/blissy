import { Schema } from "effect";

export const AuthorizationRequestReservedParameterSchema = Schema.Literal(
  "client_id",
  "code_challenge",
  "code_challenge_method",
  "redirect_uri",
  "response_type",
  "scope",
  "state",
);
