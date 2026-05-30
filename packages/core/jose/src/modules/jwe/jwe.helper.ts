import {
  AlgorithmReference,
  CryptoReference,
} from "@blissy-auth/crypto/source";
import { Effect } from "effect";

import { Base64 } from "../../utils/base64";
import type { JWE } from "./jwe";
import {
  JWEAlgorithmNotSupportedError,
  JWEDecryptionError,
  JWEEncryptionNotSupportedError,
} from "./jwe.errors";

export class Helper {
  private static encoder = new TextEncoder();
  private static decoder = new TextDecoder();

  static encrypt({
    header,
    key,
    payload,
    protectedHeader,
  }: {
    key: Uint8Array;
    payload: Uint8Array;
    protectedHeader: JWE.Header;
    header?: Record<string, JWE.HeaderValue>;
  }) {
    return Effect.gen(function* () {
      yield* Helper.validateProtectedHeader(protectedHeader);
      const algorithm = yield* AlgorithmReference;
      const crypto = yield* CryptoReference;
      const cryptoKey = yield* Helper.importKey(key);
      const iv = crypto.randomValues(new Uint8Array(12));
      const protectedSegment = yield* Base64.encode(
        Helper.encoder.encode(JSON.stringify(protectedHeader)),
      );
      const additionalData = Helper.encoder.encode(protectedSegment);
      const promise = crypto.encrypt(
        algorithm.jwe[AlgorithmReference.A256GCM].params({
          additionalData,
          iv,
        }),
        cryptoKey,
        new Uint8Array(payload),
      );
      const encrypted = new Uint8Array(yield* Effect.promise(() => promise));
      const ciphertext = encrypted.slice(0, -16);
      const tag = encrypted.slice(-16);

      return {
        ciphertext: yield* Base64.encode(ciphertext),
        encrypted_key: "",
        header,
        iv: yield* Base64.encode(iv),
        protected: protectedSegment,
        tag: yield* Base64.encode(tag),
      };
    });
  }

  static decrypt({
    ciphertextSegment,
    encryptedKeySegment,
    ivSegment,
    key,
    protectedSegment,
    tagSegment,
  }: {
    key: Uint8Array;
    protectedSegment: string;
    encryptedKeySegment: string;
    ivSegment: string;
    ciphertextSegment: string;
    tagSegment: string;
  }) {
    return Effect.gen(function* () {
      const protectedHeaderBytes = yield* Base64.decode(protectedSegment);
      const protectedHeader = JSON.parse(
        Helper.decoder.decode(protectedHeaderBytes),
      ) as JWE.Header;

      yield* Helper.validateProtectedHeader(protectedHeader);

      if (encryptedKeySegment !== "") {
        return yield* Effect.fail(
          new JWEDecryptionError({ message: "Invalid JWE ciphertext" }),
        );
      }

      const algorithm = yield* AlgorithmReference;
      const crypto = yield* CryptoReference;
      const cryptoKey = yield* Helper.importKey(key);
      const iv = yield* Base64.decode(ivSegment);
      const ciphertext = yield* Base64.decode(ciphertextSegment);
      const tag = yield* Base64.decode(tagSegment);
      const additionalData = Helper.encoder.encode(protectedSegment);
      const encrypted = new Uint8Array(ciphertext.length + tag.length);

      encrypted.set(ciphertext);
      encrypted.set(tag, ciphertext.length);

      const promise = crypto.decrypt(
        algorithm.jwe[AlgorithmReference.A256GCM].params({
          additionalData,
          iv: new Uint8Array(iv),
        }),
        cryptoKey,
        encrypted,
      );
      const decrypted = yield* Effect.tryPromise({
        try: () => promise,
        catch: () =>
          new JWEDecryptionError({ message: "Invalid JWE ciphertext" }),
      });
      const payload = new Uint8Array(decrypted);

      return { payload, protectedHeader };
    });
  }

  static importKey(key: Uint8Array) {
    return Effect.gen(function* () {
      const algorithm = yield* AlgorithmReference;
      const crypto = yield* CryptoReference;
      const promise = crypto.importKey(
        "raw",
        new Uint8Array(key),
        algorithm.jwe[AlgorithmReference.A256GCM].importKey,
        false,
        ["encrypt", "decrypt"],
      );

      return yield* Effect.promise(() => promise);
    });
  }

  static validateProtectedHeader(protectedHeader: {
    alg: string;
    enc: string;
  }): Effect.Effect<
    void,
    JWEAlgorithmNotSupportedError | JWEEncryptionNotSupportedError
  > {
    if (protectedHeader.alg === "dir" && protectedHeader.enc === "A256GCM") {
      return Effect.void;
    }

    if (protectedHeader.alg !== "dir") {
      const error = new JWEAlgorithmNotSupportedError({
        message: `Unsupported JWE algorithm: "${protectedHeader.alg}"`,
      });

      return Effect.fail(error);
    }

    const error = new JWEEncryptionNotSupportedError({
      message: `Unsupported JWE encryption: "${protectedHeader.enc}"`,
    });

    return Effect.fail(error);
  }

  static findRecipient({
    kid,
    recipients,
  }: {
    kid: string;
    recipients: JWE.Recipient[];
  }) {
    const recipient = recipients.find(
      (candidate) => candidate.header?.kid === kid,
    );

    if (recipient !== undefined) return Effect.succeed(recipient);

    const error = new JWEDecryptionError({
      message: `No JWE recipient matched kid: "${kid}"`,
    });

    return Effect.fail(error);
  }
}
