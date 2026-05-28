import type { CryptoService } from "./crypto.types";

export const defaultValue = (): CryptoService => ({
  decrypt: globalThis.crypto.subtle.decrypt.bind(globalThis.crypto.subtle),
  digest: globalThis.crypto.subtle.digest.bind(globalThis.crypto.subtle),
  encrypt: globalThis.crypto.subtle.encrypt.bind(globalThis.crypto.subtle),
  importKey: globalThis.crypto.subtle.importKey.bind(globalThis.crypto.subtle),
  randomValues: globalThis.crypto.getRandomValues.bind(globalThis.crypto),
  sign: globalThis.crypto.subtle.sign.bind(globalThis.crypto.subtle),
  verify: globalThis.crypto.subtle.verify.bind(globalThis.crypto.subtle),
});
