import { Context } from "effect";

import { A256GCM, ES256, HS256, RS256, SHA256 } from "./algorithm.constants";
import { defaultValue } from "./algorithm.defaults";
import type { AlgorithmService } from "./algorithm.types";

export class AlgorithmReference extends Context.Reference<AlgorithmReference>()(
  "@blissy-auth/crypto/AlgorithmReference",
  { defaultValue },
) {
  static A256GCM = A256GCM;
  static ES256 = ES256;
  static HS256 = HS256;
  static RS256 = RS256;
  static SHA256 = SHA256;
}

export namespace AlgorithmReference {
  export type Service = AlgorithmService;
}
