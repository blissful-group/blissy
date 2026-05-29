import { Effect } from "effect";
import { expect, it } from "vitest";

import { AuthorizationResponseValidationError } from "./authorization-response.errors";
import { Helper } from "./authorization-response.helper";

it("parses authorization callback URLs", async () => {
  const url = await Effect.runPromise(
    Helper.parseUrl("https://client.example/callback?code=abc"),
  );

  expect(url.searchParams.get("code")).toBe("abc");
});

it("rejects invalid authorization callback URLs", async () => {
  const effect = Effect.match(Helper.parseUrl("not a url"), {
    onFailure: (error) => error,
    onSuccess: () => null,
  });

  const error = await Effect.runPromise(effect);

  expect(error).toBeInstanceOf(AuthorizationResponseValidationError);
  expect(error?.message).toBe("Invalid authorization callback URL");
});

it("rejects duplicate reserved parameters", async () => {
  const url = new URL("https://client.example/callback?code=abc&code=def");
  const effect = Effect.match(Helper.validateNoDuplicateParameters(url), {
    onFailure: (error) => error,
    onSuccess: () => null,
  });

  const error = await Effect.runPromise(effect);

  expect(error).toBeInstanceOf(AuthorizationResponseValidationError);
  expect(error?._tag).toBe("AuthorizationResponseValidationError");
  expect(error?.message).toBe("Duplicate authorization response parameter");
});

it("allows duplicate non-reserved parameters", async () => {
  const url = new URL("https://client.example/callback?custom=abc&custom=def");

  await Effect.runPromise(Helper.validateNoDuplicateParameters(url));
});

it("detects reserved parameters", () => {
  expect(Helper.isReservedParameter("code")).toBe(true);
  expect(Helper.isReservedParameter("custom")).toBe(false);
});

it("validates authorization error fields", async () => {
  await expect(
    Effect.runPromise(
      Helper.validateErrorField(
        "invalid_request",
        "Invalid authorization error",
      ),
    ),
  ).resolves.toBe("invalid_request");
});

it("rejects invalid authorization error fields", async () => {
  const effect = Effect.match(
    Helper.validateErrorField('invalid"request', "Invalid authorization error"),
    {
      onFailure: (error) => error,
      onSuccess: () => null,
    },
  );

  const error = await Effect.runPromise(effect);

  expect(error).toBeInstanceOf(AuthorizationResponseValidationError);
  expect(error?.message).toBe("Invalid authorization error");
});

it("parses authorization error URIs", async () => {
  const url = await Effect.runPromise(
    Helper.parseErrorUri("https://server.example/error"),
  );

  expect(url.href).toBe("https://server.example/error");
});

it("rejects invalid authorization error URIs", async () => {
  const effect = Effect.match(Helper.parseErrorUri("not a uri"), {
    onFailure: (error) => error,
    onSuccess: () => null,
  });

  const error = await Effect.runPromise(effect);

  expect(error).toBeInstanceOf(AuthorizationResponseValidationError);
  expect(error?.message).toBe("Invalid authorization error URI");
});

it("parses authorization error responses", async () => {
  const response = await Effect.runPromise(
    Helper.parseErrorResponse(
      new URL(
        "https://client.example/callback?error=invalid_request&error_description=Invalid&error_uri=https%3A%2F%2Fserver.example%2Ferror&state=abc",
      ),
      "invalid_request",
    ),
  );

  expect(response).toEqual({
    error: "invalid_request",
    errorDescription: "Invalid",
    errorUri: "https://server.example/error",
    state: "abc",
    type: "error",
  });
});
