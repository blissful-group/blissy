import { Effect } from "effect";
import { expect, it } from "vitest";

import { OAuth2State } from "../state/state";
import { OAuth2AuthorizationResponse } from "./authorization-response";

const callbackUrl = "https://client.example/callback";

it("parses a successful authorization response from a callback URL", async () => {
  const response = await Effect.runPromise(
    OAuth2AuthorizationResponse.parse({
      callbackUrl: `${callbackUrl}?code=code-123`,
    }),
  );

  expect(response).toEqual({
    code: "code-123",
    state: undefined,
    type: "success",
  });
});

it("extracts the authorization code", async () => {
  const response = await Effect.runPromise(
    OAuth2AuthorizationResponse.parse({
      callbackUrl: `${callbackUrl}?code=code-123`,
    }),
  );

  expect(response).toMatchObject({ code: "code-123", type: "success" });
});

it("extracts the returned state", async () => {
  const response = await Effect.runPromise(
    OAuth2AuthorizationResponse.parse({
      callbackUrl: `${callbackUrl}?code=code-123&state=state-123`,
    }),
  );

  expect(response.state).toBe("state-123");
});

it("handles callback URLs with additional query parameters", async () => {
  const response = await Effect.runPromise(
    OAuth2AuthorizationResponse.parse({
      callbackUrl: `${callbackUrl}?code=code-123&iss=https%3A%2F%2Fserver.example`,
    }),
  );

  expect(response).toMatchObject({ code: "code-123", type: "success" });
});

it("allows duplicate extension response parameters", async () => {
  const response = await Effect.runPromise(
    OAuth2AuthorizationResponse.parse({
      callbackUrl: `${callbackUrl}?code=code-123&resource=one&resource=two`,
    }),
  );

  expect(response).toMatchObject({ code: "code-123", type: "success" });
});

it("rejects a callback URL without code or error", async () => {
  const effect = Effect.match(
    OAuth2AuthorizationResponse.parse({ callbackUrl }),
    {
      onFailure: (error) => error,
      onSuccess: () => null,
    },
  );

  const error = await Effect.runPromise(effect);

  expect(error).toBeInstanceOf(OAuth2AuthorizationResponse.ValidationError);
  expect(error?._tag).toBe("AuthorizationResponseValidationError");
  expect(error?.message).toBe("Invalid authorization response");
});

it("rejects a successful callback without code", async () => {
  const effect = Effect.match(
    OAuth2AuthorizationResponse.parse({ callbackUrl: `${callbackUrl}?code=` }),
    {
      onFailure: (error) => error,
      onSuccess: () => null,
    },
  );

  const error = await Effect.runPromise(effect);

  expect(error).toBeInstanceOf(OAuth2AuthorizationResponse.ValidationError);
  expect(error?._tag).toBe("AuthorizationResponseValidationError");
  expect(error?.message).toBe("Invalid authorization response");
});

it("rejects a callback with both code and error", async () => {
  const effect = Effect.match(
    OAuth2AuthorizationResponse.parse({
      callbackUrl: `${callbackUrl}?code=code-123&error=access_denied`,
    }),
    {
      onFailure: (error) => error,
      onSuccess: () => null,
    },
  );

  const error = await Effect.runPromise(effect);

  expect(error).toBeInstanceOf(OAuth2AuthorizationResponse.ValidationError);
  expect(error?._tag).toBe("AuthorizationResponseValidationError");
  expect(error?.message).toBe("Invalid authorization response");
});

it("parses an authorization error response", async () => {
  const response = await Effect.runPromise(
    OAuth2AuthorizationResponse.parse({
      callbackUrl: `${callbackUrl}?error=access_denied`,
    }),
  );

  expect(response).toEqual({
    error: "access_denied",
    errorDescription: undefined,
    errorUri: undefined,
    state: undefined,
    type: "error",
  });
});

it("extracts error", async () => {
  const response = await Effect.runPromise(
    OAuth2AuthorizationResponse.parse({
      callbackUrl: `${callbackUrl}?error=invalid_request`,
    }),
  );

  expect(response).toMatchObject({ error: "invalid_request", type: "error" });
});

it("extracts error_description", async () => {
  const response = await Effect.runPromise(
    OAuth2AuthorizationResponse.parse({
      callbackUrl: `${callbackUrl}?error=access_denied&error_description=Denied`,
    }),
  );

  expect(response).toMatchObject({
    errorDescription: "Denied",
    type: "error",
  });
});

it("extracts error_uri", async () => {
  const response = await Effect.runPromise(
    OAuth2AuthorizationResponse.parse({
      callbackUrl: `${callbackUrl}?error=access_denied&error_uri=https%3A%2F%2Fserver.example%2Ferrors%2Faccess_denied`,
    }),
  );

  expect(response).toMatchObject({
    errorUri: "https://server.example/errors/access_denied",
    type: "error",
  });
});

it("extracts state from an error response", async () => {
  const response = await Effect.runPromise(
    OAuth2AuthorizationResponse.parse({
      callbackUrl: `${callbackUrl}?error=access_denied&state=state-123`,
    }),
  );

  expect(response.state).toBe("state-123");
});

it("allows extension OAuth error codes with valid characters", async () => {
  const response = await Effect.runPromise(
    OAuth2AuthorizationResponse.parse({
      callbackUrl: `${callbackUrl}?error=custom_error`,
    }),
  );

  expect(response).toMatchObject({ error: "custom_error", type: "error" });
});

it("rejects error codes with invalid characters", async () => {
  const effect = Effect.match(
    OAuth2AuthorizationResponse.parse({
      callbackUrl: `${callbackUrl}?error=invalid%22error`,
    }),
    {
      onFailure: (error) => error,
      onSuccess: () => null,
    },
  );

  const error = await Effect.runPromise(effect);

  expect(error).toBeInstanceOf(OAuth2AuthorizationResponse.ValidationError);
  expect(error?._tag).toBe("AuthorizationResponseValidationError");
  expect(error?.message).toBe("Invalid authorization error");
});

it("rejects error descriptions with invalid characters", async () => {
  const effect = Effect.match(
    OAuth2AuthorizationResponse.parse({
      callbackUrl: `${callbackUrl}?error=access_denied&error_description=invalid%5Cdescription`,
    }),
    {
      onFailure: (error) => error,
      onSuccess: () => null,
    },
  );

  const error = await Effect.runPromise(effect);

  expect(error).toBeInstanceOf(OAuth2AuthorizationResponse.ValidationError);
  expect(error?._tag).toBe("AuthorizationResponseValidationError");
  expect(error?.message).toBe("Invalid authorization error description");
});

it("rejects duplicate reserved response parameters", async () => {
  const effect = Effect.match(
    OAuth2AuthorizationResponse.parse({
      callbackUrl: `${callbackUrl}?code=code-123&code=code-456`,
    }),
    {
      onFailure: (error) => error,
      onSuccess: () => null,
    },
  );

  const error = await Effect.runPromise(effect);

  expect(error).toBeInstanceOf(OAuth2AuthorizationResponse.ValidationError);
  expect(error?._tag).toBe("AuthorizationResponseValidationError");
  expect(error?.message).toBe("Duplicate authorization response parameter");
  expect(error).toMatchObject({ parameter: "code" });
});

it("rejects malformed error_uri", async () => {
  const effect = Effect.match(
    OAuth2AuthorizationResponse.parse({
      callbackUrl: `${callbackUrl}?error=access_denied&error_uri=not+a+url`,
    }),
    {
      onFailure: (error) => error,
      onSuccess: () => null,
    },
  );

  const error = await Effect.runPromise(effect);

  expect(error).toBeInstanceOf(OAuth2AuthorizationResponse.ValidationError);
  expect(error?._tag).toBe("AuthorizationResponseValidationError");
  expect(error?.message).toBe("Invalid authorization error URI");
});

it("rejects structurally invalid error_uri values", async () => {
  const effect = Effect.match(
    OAuth2AuthorizationResponse.parse({
      callbackUrl: `${callbackUrl}?error=access_denied&error_uri=not-a-url`,
    }),
    {
      onFailure: (error) => error,
      onSuccess: () => null,
    },
  );

  const error = await Effect.runPromise(effect);

  expect(error).toBeInstanceOf(OAuth2AuthorizationResponse.ValidationError);
  expect(error?._tag).toBe("AuthorizationResponseValidationError");
  expect(error?.message).toBe("Invalid authorization error URI");
});

it("validates returned state against expected state", async () => {
  const response = await Effect.runPromise(
    OAuth2AuthorizationResponse.parse({
      callbackUrl: `${callbackUrl}?code=code-123&state=state-123`,
      expectedState: "state-123",
    }),
  );

  expect(response).toMatchObject({ state: "state-123", type: "success" });
});

it("rejects mismatched state", async () => {
  const effect = Effect.match(
    OAuth2AuthorizationResponse.parse({
      callbackUrl: `${callbackUrl}?code=code-123&state=state-456`,
      expectedState: "state-123",
    }),
    {
      onFailure: (error) => error,
      onSuccess: () => null,
    },
  );

  const error = await Effect.runPromise(effect);

  expect(error).toBeInstanceOf(OAuth2State.ValidationError);
  expect(error?._tag).toBe("OAuth2StateValidationError");
  expect(error?.message).toBe("Invalid OAuth2 state");
});

it("rejects missing state when expected state is required", async () => {
  const effect = Effect.match(
    OAuth2AuthorizationResponse.parse({
      callbackUrl: `${callbackUrl}?code=code-123`,
      expectedState: "state-123",
    }),
    {
      onFailure: (error) => error,
      onSuccess: () => null,
    },
  );

  const error = await Effect.runPromise(effect);

  expect(error).toBeInstanceOf(OAuth2State.ValidationError);
  expect(error?._tag).toBe("OAuth2StateValidationError");
  expect(error?.message).toBe("Missing OAuth2 state");
});

it("supports query response mode", async () => {
  const response = await Effect.runPromise(
    OAuth2AuthorizationResponse.parse({
      callbackUrl: `${callbackUrl}?code=code-123`,
      responseMode: "query",
    }),
  );

  expect(response).toMatchObject({ code: "code-123", type: "success" });
});

it("rejects unsupported response modes", async () => {
  const effect = Effect.match(
    OAuth2AuthorizationResponse.parse({
      callbackUrl: `${callbackUrl}#code=code-123`,
      responseMode: "fragment" as "query",
    }),
    {
      onFailure: (error) => error,
      onSuccess: () => null,
    },
  );

  const error = await Effect.runPromise(effect);

  expect(error).toBeInstanceOf(OAuth2AuthorizationResponse.ValidationError);
  expect(error?._tag).toBe("AuthorizationResponseValidationError");
  expect(error?.message).toBe("Unsupported authorization response mode");
  expect(error).toMatchObject({ responseMode: "fragment" });
});

it("rejects an invalid callback URL", async () => {
  const effect = Effect.match(
    OAuth2AuthorizationResponse.parse({ callbackUrl: "not a url" }),
    {
      onFailure: (error) => error,
      onSuccess: () => null,
    },
  );

  const error = await Effect.runPromise(effect);

  expect(error).toBeInstanceOf(OAuth2AuthorizationResponse.ValidationError);
  expect(error?._tag).toBe("AuthorizationResponseValidationError");
  expect(error?.message).toBe("Invalid authorization callback URL");
});
