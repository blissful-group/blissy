import type { OAuth2Scope } from "../scope/scope";

export type OAuth2TokenSuccessResponse = {
  type: "success";
  accessToken: string;
  tokenType: "Bearer";
  expiresIn?: number;
  refreshToken?: string;
  scope?: OAuth2Scope.Set;
};

export type OAuth2TokenErrorResponse = {
  type: "error";
  error: string;
  errorDescription?: string;
  errorUri?: URL;
};

export type OAuth2TokenResponseValue =
  | OAuth2TokenSuccessResponse
  | OAuth2TokenErrorResponse;
