import type { JWAAlgorithm } from "../jwa/jwa.types";

export type JWSHeaderValue = string | number | boolean | null | string[];

export type JWSHeader = Record<string, JWSHeaderValue> & {
  alg: JWAAlgorithm;
  crit?: string[];
};
