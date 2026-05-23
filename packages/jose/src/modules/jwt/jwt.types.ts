export type JWTAlgorithm = "HS256" | "none";

export type JWTHeaderValue = string | number | boolean | null | string[];

export type JWTHeader = Record<string, JWTHeaderValue> & {
  alg: JWTAlgorithm;
  typ: "JWT";
};

export type JWTClaims = Record<string, unknown> & {
  iss?: string;
  sub?: string;
  aud?: string | string[];
  exp?: number;
  nbf?: number;
  iat?: number;
};
