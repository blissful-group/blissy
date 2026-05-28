import { Context } from "effect";

import { defaultValue } from "./crypto.defaults";
import type { CryptoService } from "./crypto.types";

export class CryptoReference extends Context.Reference<CryptoReference>()(
  "@blissy-auth/crypto/CryptoReference",
  { defaultValue },
) {}

export namespace CryptoReference {
  export type Service = CryptoService;
}
