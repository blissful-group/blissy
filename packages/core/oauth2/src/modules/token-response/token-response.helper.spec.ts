import { Effect } from "effect";
import { expect, it } from "vitest";

import { OAuth2TokenResponseValidationError } from "./token-response.errors";
import { Helper } from "./token-response.helper";

it("parses bearer token types", async () => {
  await expect(
    Effect.runPromise(Helper.parseTokenType("bearer")),
  ).resolves.toBe("Bearer");
});

it("parses token response records", async () => {
  const record = await Effect.runPromise(
    Helper.parseRecord({ access_token: "token" }),
  );

  expect(record.access_token).toBe("token");
});

it("rejects invalid token response records", async () => {
  const effect = Effect.match(Helper.parseRecord([]), {
    onFailure: (error) => error,
    onSuccess: () => null,
  });

  const error = await Effect.runPromise(effect);

  expect(error).toBeInstanceOf(OAuth2TokenResponseValidationError);
  expect(error?.message).toBe("Invalid token response");
});

it("rejects invalid token types", async () => {
  const effect = Effect.match(Helper.parseTokenType("mac"), {
    onFailure: (error) => error,
    onSuccess: () => null,
  });

  const error = await Effect.runPromise(effect);

  expect(error).toBeInstanceOf(OAuth2TokenResponseValidationError);
  expect(error?._tag).toBe("OAuth2TokenResponseValidationError");
  expect(error?.message).toBe("Invalid token type");
});

it("parses expires_in", async () => {
  await expect(Effect.runPromise(Helper.parseExpiresIn(60))).resolves.toBe(60);
});

it("rejects invalid expires_in", async () => {
  const effect = Effect.match(Helper.parseExpiresIn(-1), {
    onFailure: (error) => error,
    onSuccess: () => null,
  });

  const error = await Effect.runPromise(effect);

  expect(error).toBeInstanceOf(OAuth2TokenResponseValidationError);
  expect(error?.message).toBe("Invalid expires_in");
});

it("parses token error fields", async () => {
  await expect(
    Effect.runPromise(
      Helper.parseErrorField("invalid_grant", "Invalid token error"),
    ),
  ).resolves.toBe("invalid_grant");
});

it("rejects invalid token error fields", async () => {
  const effect = Effect.match(
    Helper.parseErrorField('invalid"grant', "Invalid token error"),
    {
      onFailure: (error) => error,
      onSuccess: () => null,
    },
  );

  const error = await Effect.runPromise(effect);

  expect(error).toBeInstanceOf(OAuth2TokenResponseValidationError);
  expect(error?.message).toBe("Invalid token error");
});

it("parses token error URIs", async () => {
  const url = await Effect.runPromise(
    Helper.parseErrorUri("https://server.example/error"),
  );

  expect(url.href).toBe("https://server.example/error");
});

it("rejects invalid token error URIs", async () => {
  const effect = Effect.match(Helper.parseErrorUri("not a uri"), {
    onFailure: (error) => error,
    onSuccess: () => null,
  });

  const error = await Effect.runPromise(effect);

  expect(error).toBeInstanceOf(OAuth2TokenResponseValidationError);
  expect(error?.message).toBe("Invalid token error URI");
});

it("parses non-empty strings", async () => {
  await expect(
    Effect.runPromise(
      Helper.parseNonEmptyString("token", "Invalid access token"),
    ),
  ).resolves.toBe("token");
});

it("rejects empty strings", async () => {
  const effect = Effect.match(
    Helper.parseNonEmptyString("", "Invalid access token"),
    {
      onFailure: (error) => error,
      onSuccess: () => null,
    },
  );

  const error = await Effect.runPromise(effect);

  expect(error).toBeInstanceOf(OAuth2TokenResponseValidationError);
  expect(error?.message).toBe("Invalid access token");
});

it("parses successful token responses", async () => {
  const response = await Effect.runPromise(
    Helper.parseSuccessResponse({
      access_token: "token",
      expires_in: 60,
      refresh_token: "refresh",
      scope: "read write",
      token_type: "Bearer",
    }),
  );

  expect(response).toMatchObject({
    accessToken: "token",
    expiresIn: 60,
    refreshToken: "refresh",
    scope: ["read", "write"],
    tokenType: "Bearer",
    type: "success",
  });
});

it("parses token error responses", async () => {
  const response = await Effect.runPromise(
    Helper.parseErrorResponse({
      error: "invalid_grant",
      error_description: "Invalid grant",
      error_uri: "https://server.example/error",
    }),
  );

  expect(response).toMatchObject({
    error: "invalid_grant",
    errorDescription: "Invalid grant",
    errorUri: new URL("https://server.example/error"),
    type: "error",
  });
});
