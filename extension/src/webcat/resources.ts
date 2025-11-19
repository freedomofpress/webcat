const ALL_TYPES = [
  "main_frame",
  "sub_frame",
  "stylesheet",
  "script",
  "image",
  "font",
  "object",
  "xmlhttprequest",
  "ping",
  "csp_report",
  "media",
  "websocket",
  "other",
  "xslt",
  "beacon",
  "imageset",
  "object_subrequest",
  "speculative",
  "web_manifest",
] satisfies browser.webRequest.ResourceType[];

export const NON_FRAME_TYPES = ALL_TYPES.filter(
  (t) => t !== "main_frame" && t !== "sub_frame",
);

export const PASS_THROUGH_TYPES = new Set<browser.webRequest.ResourceType>([
  "image",
  "imageset",
  "media",
  "font",
  "websocket",
  "xmlhttprequest",
  "ping",
  "speculative",
  "other",
]);
