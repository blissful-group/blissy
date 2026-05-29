import { Effect } from "effect";

import {
  JWEAlgorithmNotSupportedError,
  JWEDecryptionError,
  JWEEncryptionNotSupportedError,
} from "./jwe.errors";
import { Helper } from "./jwe.helper";
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
  private static Helper = Helper;

  static AlgorithmNotSupportedError = JWEAlgorithmNotSupportedError;
  static DecryptionError = JWEDecryptionError;
  static EncryptionNotSupportedError = JWEEncryptionNotSupportedError;

  /**
   * Creates a compact JWE serialization.
   */
  static encryptCompact(input: {
    key: Uint8Array;
    payload: Uint8Array;
    protectedHeader: JWEHeader;
  }) {
    return Effect.gen(function* () {
      const entry = yield* JWE.Helper.encrypt(input);

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

      return yield* JWE.Helper.decrypt({
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
      const entry = yield* JWE.Helper.encrypt(input);

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
      const entry = yield* JWE.Helper.encrypt({
        key,
        payload,
        protectedHeader,
      });

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
      const recipient = yield* JWE.Helper.findRecipient({
        kid,
        recipients: serialization.recipients,
      });

      const decrypted = yield* JWE.Helper.decrypt({
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
}

export declare namespace JWE {
  export type Algorithm = JWEAlgorithm;
  export type Encryption = JWEEncryption;
  export type Header = JWEHeader;
  export type HeaderValue = JWEHeaderValue;
  export type Recipient = JWERecipient;
}
