export type OAuth2TokenRequestAuthentication = {
  bodyParameters: Readonly<Record<string, string>>;
  headers: Readonly<Record<string, string>>;
};

export type OAuth2TokenRequestExtensionParameters = Readonly<
  Record<string, string | null | undefined>
>;

export type OAuth2TokenRequestValue = {
  method: "POST";
  url: URL;
  headers: Record<string, string>;
  body: URLSearchParams;
};
