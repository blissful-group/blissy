import { Data } from "effect";

export class OIDCDiscoveryValidationError extends Data.TaggedError(
  "OIDCDiscoveryValidationError",
)<{
  message:
    | "Invalid provider metadata"
    | "Invalid issuer"
    | "Invalid authorization endpoint"
    | "Invalid token endpoint"
    | "Invalid userinfo endpoint"
    | "Invalid jwks uri"
    | "Invalid response types supported"
    | "Invalid subject types supported"
    | "Invalid id token signing alg values supported"
    | "Invalid scopes supported"
    | "Invalid claims supported"
    | "Invalid grant types supported"
    | "Invalid token endpoint auth methods supported";
}> {}
