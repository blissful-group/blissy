import type { AlgorithmReference } from "./algorithm";
import { A256GCM, ES256, HS256, RS256, SHA256 } from "./algorithm.constants";

export const defaultValue = (): AlgorithmReference.Service => ({
  digest: {
    [SHA256]: "SHA-256",
  },
  jwa: {
    [ES256]: {
      importKey: { name: "ECDSA", namedCurve: "P-256" },
      sign: { hash: "SHA-256", name: "ECDSA" },
    },
    [HS256]: {
      importKey: { hash: "SHA-256", name: "HMAC" },
      sign: "HMAC",
    },
    [RS256]: {
      importKey: { hash: "SHA-256", name: "RSASSA-PKCS1-v1_5" },
      sign: "RSASSA-PKCS1-v1_5",
    },
  },
  jwe: {
    [A256GCM]: {
      importKey: { length: 256, name: "AES-GCM" },
      params: ({ additionalData, iv }) => ({
        additionalData,
        iv,
        name: "AES-GCM",
        tagLength: 128,
      }),
    },
  },
});
