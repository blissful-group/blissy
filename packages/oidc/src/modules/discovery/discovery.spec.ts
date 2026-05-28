import { Effect } from "effect";
import { expect, it } from "vitest";

import { OIDCDiscovery } from "./discovery";

const metadata = {
  authorization_endpoint: "https://server.example/authorize",
  claims_supported: ["sub", "email"],
  grant_types_supported: ["authorization_code"],
  id_token_signing_alg_values_supported: ["RS256"],
  issuer: "https://server.example",
  jwks_uri: "https://server.example/jwks.json",
  response_types_supported: ["code"],
  scopes_supported: ["openid", "profile", "email"],
  subject_types_supported: ["public"],
  token_endpoint: "https://server.example/token",
  token_endpoint_auth_methods_supported: ["client_secret_basic"],
  userinfo_endpoint: "https://server.example/userinfo",
};

it("builds the standard provider configuration URL", async () => {
  const url = await Effect.runPromise(
    OIDCDiscovery.configurationUrl("https://server.example/tenant/"),
  );

  expect(url.href).toBe(
    "https://server.example/tenant/.well-known/openid-configuration",
  );
});

it("drops query and fragment when building configuration URL", async () => {
  const url = await Effect.runPromise(
    OIDCDiscovery.configurationUrl("https://server.example?foo=bar#fragment"),
  );

  expect(url.href).toBe(
    "https://server.example/.well-known/openid-configuration",
  );
});

it("parses provider metadata", async () => {
  const parsed = await Effect.runPromise(OIDCDiscovery.parse(metadata));

  expect(parsed).toMatchObject({
    claimsSupported: ["sub", "email"],
    grantTypesSupported: ["authorization_code"],
    idTokenSigningAlgValuesSupported: ["RS256"],
    responseTypesSupported: ["code"],
    scopesSupported: ["openid", "profile", "email"],
    subjectTypesSupported: ["public"],
    tokenEndpointAuthMethodsSupported: ["client_secret_basic"],
  });
  expect(parsed.issuer.href).toBe("https://server.example/");
  expect(parsed.authorizationEndpoint.href).toBe(
    "https://server.example/authorize",
  );
  expect(parsed.tokenEndpoint?.href).toBe("https://server.example/token");
  expect(parsed.userinfoEndpoint?.href).toBe("https://server.example/userinfo");
  expect(parsed.jwksUri.href).toBe("https://server.example/jwks.json");
});

it("parses provider metadata with only required fields", async () => {
  const parsed = await Effect.runPromise(
    OIDCDiscovery.parse({
      authorization_endpoint: metadata.authorization_endpoint,
      id_token_signing_alg_values_supported:
        metadata.id_token_signing_alg_values_supported,
      issuer: metadata.issuer,
      jwks_uri: metadata.jwks_uri,
      response_types_supported: metadata.response_types_supported,
      subject_types_supported: metadata.subject_types_supported,
    }),
  );

  expect(parsed.tokenEndpoint).toBeUndefined();
  expect(parsed.userinfoEndpoint).toBeUndefined();
});

it("rejects non-object provider metadata", async () => {
  const effect = Effect.match(OIDCDiscovery.parse(null), {
    onFailure: (error) => error,
    onSuccess: () => null,
  });

  const error = await Effect.runPromise(effect);

  expect(error).toBeInstanceOf(OIDCDiscovery.ValidationError);
  expect(error?._tag).toBe("OIDCDiscoveryValidationError");
  expect(error?.message).toBe("Invalid provider metadata");
});

it("rejects invalid issuer", async () => {
  const effect = Effect.match(
    OIDCDiscovery.parse({
      ...metadata,
      issuer: "not a url",
    }),
    {
      onFailure: (error) => error,
      onSuccess: () => null,
    },
  );

  const error = await Effect.runPromise(effect);

  expect(error).toBeInstanceOf(OIDCDiscovery.ValidationError);
  expect(error?.message).toBe("Invalid issuer");
});

it("rejects empty required metadata arrays", async () => {
  const effect = Effect.match(
    OIDCDiscovery.parse({
      ...metadata,
      response_types_supported: [],
    }),
    {
      onFailure: (error) => error,
      onSuccess: () => null,
    },
  );

  const error = await Effect.runPromise(effect);

  expect(error).toBeInstanceOf(OIDCDiscovery.ValidationError);
  expect(error?.message).toBe("Invalid response types supported");
});

it("rejects non-string metadata array values", async () => {
  const effect = Effect.match(
    OIDCDiscovery.parse({
      ...metadata,
      scopes_supported: ["openid", 123],
    }),
    {
      onFailure: (error) => error,
      onSuccess: () => null,
    },
  );

  const error = await Effect.runPromise(effect);

  expect(error).toBeInstanceOf(OIDCDiscovery.ValidationError);
  expect(error?.message).toBe("Invalid scopes supported");
});
