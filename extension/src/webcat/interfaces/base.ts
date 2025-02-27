export enum Issuers {
  google = "https://accounts.google.com",
  microsoft = "https://login.microsoftonline.com",
  github = "https://github.com/login/oauth",
  gitlab = "https://gitlab.com",
}

export enum metadataRequestSource {
  main_frame,
  sub_frame,
  worker,
}

export type Signer = [issuer: Issuers, identity: string];

export interface Policy {
  signers: Set<Signer>;
  threshold: number;
  subframes?: string[];
}
