import { Context } from "effect";

import type { OAuth2CryptoService } from "./crypto.types";

export class OAuth2Crypto extends Context.Reference<OAuth2Crypto>()(
  "@blissy-auth/oauth2/OAuth2Crypto",
  {
    defaultValue: (): OAuth2CryptoService => ({
      digest: globalThis.crypto.subtle.digest.bind(globalThis.crypto.subtle),
      randomValues: globalThis.crypto.getRandomValues.bind(globalThis.crypto),
    }),
  },
) {}

export namespace OAuth2Crypto {
  export type Service = OAuth2CryptoService;
}
