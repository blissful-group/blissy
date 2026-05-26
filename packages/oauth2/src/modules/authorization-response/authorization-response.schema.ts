import { Schema } from "effect";

export const ReservedParameterSchema = Schema.Literal(
  "code",
  "error",
  "error_description",
  "error_uri",
  "state",
);

export const AuthorizationErrorFieldSchema = Schema.String.pipe(
  Schema.pattern(/^[\u0020-\u0021\u0023-\u005B\u005D-\u007E]+$/u),
);

export const AuthorizationErrorUriSchema = Schema.String.pipe(
  Schema.pattern(/^[\u0021\u0023-\u005B\u005D-\u007E]+$/u),
);
