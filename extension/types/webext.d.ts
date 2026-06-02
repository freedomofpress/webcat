declare namespace browser.webRequest {
  interface _OnHeadersReceivedDetails {
    fromCache?: boolean;
    frameAncestors?: { url: string; frameId: number }[];
  }
  interface _OnBeforeRequestDetails {
    frameAncestors?: { url: string; frameId: number }[];
  }
}
