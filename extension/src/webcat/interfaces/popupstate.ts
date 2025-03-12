import { Signer } from "./base";

export class PopupState {
  readonly fqdn: string;
  readonly tabId: number;
  // In the popup, if undefined mark it as loading. False means something failed.
  valid_headers: boolean | undefined;
  valid_manifest: boolean | undefined;
  valid_csp: boolean | undefined;
  valid_index: boolean | undefined;
  valid_signers: Signer[];
  valid_sources: Set<string>;
  invalid_sources: Set<string>;
  invalid_assets: string[];
  threshold: number | undefined;
  loaded_assets: string[];
  webcat: {
    version: number;
    list_count: number;
    list_last_update: number;
    list_version: string;
  };

  constructor(
    fqdn: string,
    tabId: number,
    version: number,
    list_count: number,
    list_last_update: number,
    list_version: string,
  ) {
    this.fqdn = fqdn;
    this.tabId = tabId;
    this.valid_headers = undefined;
    this.valid_manifest = undefined;
    this.valid_csp = undefined;
    this.valid_index = undefined;
    this.valid_signers = [];
    this.valid_sources = new Set();
    this.invalid_sources = new Set();
    this.invalid_assets = [];
    this.loaded_assets = [];
    this.threshold = undefined;
    this.webcat = {
      version: version,
      list_count: list_count,
      // TODO
      list_last_update: list_last_update,
      list_version: list_version,
    };
  }
}
