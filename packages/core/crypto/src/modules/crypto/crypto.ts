import { Context } from "effect";

import { defaultValue } from "./crypto.defaults";

export class CryptoReference extends Context.Reference<CryptoReference>()(
  "@blissy-auth/crypto/CryptoReference",
  { defaultValue },
) {}

export namespace CryptoReference {
  export type Service = {
    randomValues: (bytes: Uint8Array<ArrayBuffer>) => Uint8Array<ArrayBuffer>;
    digest: (
      algorithm: AlgorithmIdentifier,
      data: BufferSource,
    ) => Promise<ArrayBuffer>;
    importKey: SubtleCrypto["importKey"];
    sign: SubtleCrypto["sign"];
    verify: SubtleCrypto["verify"];
    encrypt: SubtleCrypto["encrypt"];
    decrypt: SubtleCrypto["decrypt"];
  };
}
