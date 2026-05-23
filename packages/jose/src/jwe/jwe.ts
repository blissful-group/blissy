import { Effect } from "effect";

import { Base64 } from "../utils/base64";
import {
  JWEAlgorithmNotSupportedError,
  JWEDecryptionError,
  JWEEncryptionNotSupportedError,
} from "./jwe.errors";
import type {
  JWEAlgorithm,
  JWEEncryption,
  JWEHeader,
  JWEHeaderValue,
  JWERecipient,
} from "./jwe.types";

/**
 * Creates and decrypts JSON Web Encryption serializations using dir and A256GCM.
 */
export class JWE {
  static AlgorithmNotSupportedError = JWEAlgorithmNotSupportedError;
  static DecryptionError = JWEDecryptionError;
  static EncryptionNotSupportedError = JWEEncryptionNotSupportedError;

  private static encoder = new TextEncoder();
  private static decoder = new TextDecoder();

  /**
   * Creates a compact JWE serialization.
   */
  static encryptCompact(input: {
    key: Uint8Array;
    payload: Uint8Array;
    protectedHeader: JWEHeader;
  }) {
    return Effect.gen(function* () {
      const entry = yield* JWE.encrypt(input);

      return [
        entry.protected,
        entry.encrypted_key,
        entry.iv,
        entry.ciphertext,
        entry.tag,
      ].join(".");
    });
  }

  /**
   * Decrypts a compact JWE serialization.
   */
  static decryptCompact({ key, token }: { key: Uint8Array; token: string }) {
    return Effect.gen(function* () {
      const segments = token.split(".");

      if (segments.length !== 5) {
        return yield* Effect.fail(
          new JWEDecryptionError({ message: "Invalid JWE ciphertext" }),
        );
      }

      const [
        protectedSegment,
        encryptedKeySegment,
        ivSegment,
        ciphertextSegment,
        tagSegment,
      ] = segments;

      return yield* JWE.decrypt({
        key,
        protectedSegment: protectedSegment!,
        encryptedKeySegment: encryptedKeySegment!,
        ivSegment: ivSegment!,
        ciphertextSegment: ciphertextSegment!,
        tagSegment: tagSegment!,
      });
    });
  }

  /**
   * Creates a flattened JSON JWE serialization.
   */
  static encryptFlattened(input: {
    key: Uint8Array;
    payload: Uint8Array;
    protectedHeader: JWEHeader;
    header?: Record<string, JWEHeaderValue>;
  }) {
    return Effect.gen(function* () {
      const entry = yield* JWE.encrypt(input);

      return {
        ciphertext: entry.ciphertext,
        encrypted_key: entry.encrypted_key,
        header: entry.header,
        iv: entry.iv,
        protected: entry.protected,
        tag: entry.tag,
      };
    });
  }

  /**
   * Creates a general JSON JWE serialization.
   */
  static encryptGeneral({
    key,
    payload,
    protectedHeader,
    recipients,
  }: {
    key: Uint8Array;
    payload: Uint8Array;
    protectedHeader: JWEHeader;
    recipients: Array<{
      header?: Record<string, JWEHeaderValue>;
    }>;
  }) {
    return Effect.gen(function* () {
      const entry = yield* JWE.encrypt({ key, payload, protectedHeader });

      return {
        ciphertext: entry.ciphertext,
        iv: entry.iv,
        protected: entry.protected,
        recipients: recipients.map((recipient) => ({
          encrypted_key: "",
          header: recipient.header,
        })),
        tag: entry.tag,
      };
    });
  }

  /**
   * Decrypts a general JSON JWE serialization for the matching recipient.
   */
  static decryptGeneral({
    key,
    kid,
    serialization,
  }: {
    key: Uint8Array;
    serialization: {
      ciphertext: string;
      iv: string;
      protected: string;
      recipients: JWERecipient[];
      tag: string;
    };
    kid: string;
  }) {
    return Effect.gen(function* () {
      const recipient = serialization.recipients.find(
        (candidate) => candidate.header?.kid === kid,
      );

      if (recipient === undefined) {
        return yield* Effect.fail(
          new JWEDecryptionError({
            message: `No JWE recipient matched kid: "${kid}"`,
          }),
        );
      }

      const decrypted = yield* JWE.decrypt({
        key,
        protectedSegment: serialization.protected,
        encryptedKeySegment: recipient.encrypted_key,
        ivSegment: serialization.iv,
        ciphertextSegment: serialization.ciphertext,
        tagSegment: serialization.tag,
      });

      return {
        payload: decrypted.payload,
        protectedHeader: decrypted.protectedHeader,
        recipient,
      };
    });
  }

  private static encrypt({
    header,
    key,
    payload,
    protectedHeader,
  }: {
    key: Uint8Array;
    payload: Uint8Array;
    protectedHeader: JWEHeader;
    header?: Record<string, JWEHeaderValue>;
  }) {
    return Effect.gen(function* () {
      yield* JWE.validateProtectedHeader(protectedHeader);
      const cryptoKey = yield* JWE.importKey(key);
      const iv = crypto.getRandomValues(new Uint8Array(12));
      const protectedSegment = yield* Base64.encode(
        JWE.encoder.encode(JSON.stringify(protectedHeader)),
      );
      const additionalData = JWE.encoder.encode(protectedSegment);
      const promise = crypto.subtle.encrypt(
        {
          additionalData,
          iv,
          name: "AES-GCM",
          tagLength: 128,
        },
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

  private static decrypt({
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
        JWE.decoder.decode(protectedHeaderBytes),
      ) as JWEHeader;

      yield* JWE.validateProtectedHeader(protectedHeader);

      if (encryptedKeySegment !== "") {
        return yield* Effect.fail(
          new JWEDecryptionError({ message: "Invalid JWE ciphertext" }),
        );
      }

      const cryptoKey = yield* JWE.importKey(key);
      const iv = yield* Base64.decode(ivSegment);
      const ciphertext = yield* Base64.decode(ciphertextSegment);
      const tag = yield* Base64.decode(tagSegment);
      const additionalData = JWE.encoder.encode(protectedSegment);
      const encrypted = new Uint8Array(ciphertext.length + tag.length);

      encrypted.set(ciphertext);
      encrypted.set(tag, ciphertext.length);

      const promise = crypto.subtle.decrypt(
        {
          additionalData,
          iv: new Uint8Array(iv),
          name: "AES-GCM",
          tagLength: 128,
        },
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

  private static importKey(key: Uint8Array) {
    const promise = crypto.subtle.importKey(
      "raw",
      new Uint8Array(key),
      { length: 256, name: "AES-GCM" },
      false,
      ["encrypt", "decrypt"],
    );

    return Effect.promise(() => promise);
  }

  private static validateProtectedHeader(protectedHeader: {
    alg: string;
    enc: string;
  }) {
    return Effect.gen(function* () {
      if (protectedHeader.alg !== "dir") {
        const error = new JWEAlgorithmNotSupportedError({
          message: `Unsupported JWE algorithm: "${protectedHeader.alg}"`,
        });

        return yield* Effect.fail(error);
      }

      if (protectedHeader.enc !== "A256GCM") {
        const error = new JWEEncryptionNotSupportedError({
          message: `Unsupported JWE encryption: "${protectedHeader.enc}"`,
        });

        return yield* Effect.fail(error);
      }
    });
  }
}

export declare namespace JWE {
  export type Algorithm = JWEAlgorithm;
  export type Encryption = JWEEncryption;
  export type Header = JWEHeader;
  export type HeaderValue = JWEHeaderValue;
  export type Recipient = JWERecipient;
}
