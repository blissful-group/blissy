import { Context } from "effect";

import type { CryptoService } from "./crypto.types";

export class CryptoReference extends Context.Reference<CryptoReference>()(
  "@blissy-auth/crypto/CryptoReference",
  {
    defaultValue: (): CryptoService => ({
      digest: globalThis.crypto.subtle.digest.bind(globalThis.crypto.subtle),
      randomValues: globalThis.crypto.getRandomValues.bind(globalThis.crypto),
    }),
  },
) {}

export namespace CryptoReference {
  export type Service = CryptoService;
}
