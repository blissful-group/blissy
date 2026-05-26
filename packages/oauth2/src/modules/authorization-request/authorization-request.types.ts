import type { OAuth2PKCE } from "../pkce/pkce";
import type { OAuth2Scope } from "../scope/scope";

export type AuthorizationCodeRequestOptions = {
  authorizationEndpoint: string;
  clientId: string;
  redirectUri: string;
  scope?: OAuth2Scope.Set;
  state?: string;
  codeChallenge?: string;
  codeChallengeMethod?: OAuth2PKCE.CodeChallengeMethod;
  parameters?: Readonly<Record<string, string>>;
};
