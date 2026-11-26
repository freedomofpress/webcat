declare namespace browser.webRequest {
  interface _OnHeadersReceivedDetails {
    fromCache?: boolean;
    frameAncestors?: { url: string; frameId: number }[];
  }
  interface _OnBeforeRequestDetails {
    frameAncestors?: { url: string; frameId: number }[];
  }
}

// Firefox 153+; absent on older versions. Drop once @types/firefox-webext-browser covers it.
declare namespace browser.publicSuffix {
  function getDomain(
    hostname: string,
    options?: {
      allowIPAddress?: boolean;
      allowPlainSuffix?: boolean;
      allowUnknownSuffix?: boolean;
    },
  ): string | null;
}
