import { Effect } from "effect";
import { expect, it } from "vitest";

import { OIDCDiscoveryValidationError } from "./discovery.errors";
import { Helper } from "./discovery.helper";

it("parses provider metadata records", async () => {
  const record = await Effect.runPromise(
    Helper.parseRecord({ issuer: "https://issuer.example" }),
  );

  expect(record.issuer).toBe("https://issuer.example");
});

it("rejects invalid provider metadata records", async () => {
  const effect = Effect.match(Helper.parseRecord(null), {
    onFailure: (error) => error,
    onSuccess: () => null,
  });

  const error = await Effect.runPromise(effect);

  expect(error).toBeInstanceOf(OIDCDiscoveryValidationError);
  expect(error?.message).toBe("Invalid provider metadata");
});

it("parses required metadata URLs", async () => {
  await expect(
    Effect.runPromise(Helper.issuer({ issuer: "https://issuer.example" })),
  ).resolves.toEqual(new URL("https://issuer.example"));
  await expect(
    Effect.runPromise(
      Helper.authorizationEndpoint({
        authorization_endpoint: "https://issuer.example/authorize",
      }),
    ),
  ).resolves.toEqual(new URL("https://issuer.example/authorize"));
  await expect(
    Effect.runPromise(
      Helper.jwksUri({ jwks_uri: "https://issuer.example/jwks" }),
    ),
  ).resolves.toEqual(new URL("https://issuer.example/jwks"));
});

it("parses optional metadata URLs", async () => {
  await expect(
    Effect.runPromise(
      Helper.tokenEndpoint({ token_endpoint: "https://issuer.example/token" }),
    ),
  ).resolves.toEqual(new URL("https://issuer.example/token"));
  await expect(
    Effect.runPromise(
      Helper.userinfoEndpoint({
        userinfo_endpoint: "https://issuer.example/userinfo",
      }),
    ),
  ).resolves.toEqual(new URL("https://issuer.example/userinfo"));
});

it("returns undefined for missing optional metadata URLs", async () => {
  await expect(
    Effect.runPromise(Helper.tokenEndpoint({})),
  ).resolves.toBeUndefined();
  await expect(
    Effect.runPromise(Helper.userinfoEndpoint({})),
  ).resolves.toBeUndefined();
});

it("parses required metadata arrays", async () => {
  await expect(
    Effect.runPromise(
      Helper.responseTypes({ response_types_supported: ["code"] }),
    ),
  ).resolves.toEqual(["code"]);
  await expect(
    Effect.runPromise(
      Helper.subjectTypes({ subject_types_supported: ["public"] }),
    ),
  ).resolves.toEqual(["public"]);
  await expect(
    Effect.runPromise(
      Helper.idTokenAlgs({ id_token_signing_alg_values_supported: ["RS256"] }),
    ),
  ).resolves.toEqual(["RS256"]);
});

it("parses optional metadata arrays", async () => {
  await expect(
    Effect.runPromise(Helper.scopes({ scopes_supported: ["openid"] })),
  ).resolves.toEqual(["openid"]);
  await expect(
    Effect.runPromise(Helper.claims({ claims_supported: ["sub"] })),
  ).resolves.toEqual(["sub"]);
  await expect(
    Effect.runPromise(
      Helper.grantTypes({ grant_types_supported: ["authorization_code"] }),
    ),
  ).resolves.toEqual(["authorization_code"]);
  await expect(
    Effect.runPromise(
      Helper.tokenMethods({
        token_endpoint_auth_methods_supported: ["client_secret_basic"],
      }),
    ),
  ).resolves.toEqual(["client_secret_basic"]);
});

it("returns undefined for missing optional metadata arrays", async () => {
  await expect(Effect.runPromise(Helper.scopes({}))).resolves.toBeUndefined();
  await expect(Effect.runPromise(Helper.claims({}))).resolves.toBeUndefined();
  await expect(
    Effect.runPromise(Helper.grantTypes({})),
  ).resolves.toBeUndefined();
  await expect(
    Effect.runPromise(Helper.tokenMethods({})),
  ).resolves.toBeUndefined();
});

it("parses URL strings", async () => {
  await expect(
    Effect.runPromise(
      Helper.parseUrlString("https://issuer.example", "Invalid issuer"),
    ),
  ).resolves.toEqual(new URL("https://issuer.example"));
});

it("rejects invalid URL strings", async () => {
  const effect = Effect.match(
    Helper.parseUrlString("not a url", "Invalid issuer"),
    {
      onFailure: (error) => error,
      onSuccess: () => null,
    },
  );

  const error = await Effect.runPromise(effect);

  expect(error).toBeInstanceOf(OIDCDiscoveryValidationError);
  expect(error?.message).toBe("Invalid issuer");
});

it("parses issuer URLs from unknown input", async () => {
  await expect(
    Effect.runPromise(
      Helper.parseUrl("https://issuer.example", "Invalid issuer"),
    ),
  ).resolves.toEqual(new URL("https://issuer.example"));
});

it("rejects invalid issuer URLs", async () => {
  const effect = Effect.match(Helper.parseUrl("not a url", "Invalid issuer"), {
    onFailure: (error) => error,
    onSuccess: () => null,
  });

  const error = await Effect.runPromise(effect);

  expect(error).toBeInstanceOf(OIDCDiscoveryValidationError);
  expect(error?.message).toBe("Invalid issuer");
});

it("parses string arrays", async () => {
  await expect(
    Effect.runPromise(
      Helper.parseStringArray(["openid"], "Invalid scopes supported"),
    ),
  ).resolves.toEqual(["openid"]);
});

it("rejects invalid string arrays", async () => {
  const effect = Effect.match(
    Helper.parseStringArray([], "Invalid scopes supported"),
    {
      onFailure: (error) => error,
      onSuccess: () => null,
    },
  );

  const error = await Effect.runPromise(effect);

  expect(error).toBeInstanceOf(OIDCDiscoveryValidationError);
  expect(error?._tag).toBe("OIDCDiscoveryValidationError");
  expect(error?.message).toBe("Invalid scopes supported");
});

it("rejects string arrays containing invalid items", async () => {
  const effect = Effect.match(
    Helper.parseStringArray(["openid", ""], "Invalid scopes supported"),
    {
      onFailure: (error) => error,
      onSuccess: () => null,
    },
  );

  const error = await Effect.runPromise(effect);

  expect(error).toBeInstanceOf(OIDCDiscoveryValidationError);
  expect(error?._tag).toBe("OIDCDiscoveryValidationError");
  expect(error?.message).toBe("Invalid scopes supported");
});
