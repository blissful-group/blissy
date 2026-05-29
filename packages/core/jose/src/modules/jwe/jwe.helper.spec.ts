import { Effect } from "effect";
import { expect, it } from "vitest";

import {
  JWEAlgorithmNotSupportedError,
  JWEDecryptionError,
  JWEEncryptionNotSupportedError,
} from "./jwe.errors";
import { Helper } from "./jwe.helper";

it("allows supported protected headers", async () => {
  await Effect.runPromise(
    Helper.validateProtectedHeader({ alg: "dir", enc: "A256GCM" }),
  );
});

it("rejects unsupported algorithms", async () => {
  const effect = Effect.match(
    Helper.validateProtectedHeader({ alg: "RSA-OAEP", enc: "A256GCM" }),
    {
      onFailure: (error) => error,
      onSuccess: () => null,
    },
  );

  const error = await Effect.runPromise(effect);

  expect(error).toBeInstanceOf(JWEAlgorithmNotSupportedError);
  expect(error?._tag).toBe("JWEAlgorithmNotSupportedError");
  expect(error?.message).toBe('Unsupported JWE algorithm: "RSA-OAEP"');
});

it("rejects unsupported encryption", async () => {
  const effect = Effect.match(
    Helper.validateProtectedHeader({ alg: "dir", enc: "A128GCM" }),
    {
      onFailure: (error) => error,
      onSuccess: () => null,
    },
  );

  const error = await Effect.runPromise(effect);

  expect(error).toBeInstanceOf(JWEEncryptionNotSupportedError);
  expect(error?._tag).toBe("JWEEncryptionNotSupportedError");
  expect(error?.message).toBe('Unsupported JWE encryption: "A128GCM"');
});

it("finds matching recipients", async () => {
  const recipient = await Effect.runPromise(
    Helper.findRecipient({
      kid: "sig-1",
      recipients: [
        { encrypted_key: "", header: { kid: "sig-1" } },
        { encrypted_key: "", header: { kid: "sig-2" } },
      ],
    }),
  );

  expect(recipient.header?.kid).toBe("sig-1");
});

it("rejects missing recipients", async () => {
  const effect = Effect.match(
    Helper.findRecipient({
      kid: "sig-3",
      recipients: [{ encrypted_key: "", header: { kid: "sig-1" } }],
    }),
    {
      onFailure: (error) => error,
      onSuccess: () => null,
    },
  );

  const error = await Effect.runPromise(effect);

  expect(error).toBeInstanceOf(JWEDecryptionError);
  expect(error?._tag).toBe("JWEDecryptionError");
  expect(error?.message).toBe('No JWE recipient matched kid: "sig-3"');
});
