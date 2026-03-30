import contentHooks from "./../../dist/hooks/content.js?raw";
import pageHooks from "./../../dist/hooks/page.js?raw";
import { hooksType } from "./interfaces/base";

export function getHooks(type: hooksType) {
  // This just patches the script string dynamically adding per-origin WASM hashes
  if (type === hooksType.page) {
    return pageHooks;
  } else if (type === hooksType.content_script) {
    return contentHooks;
  } else {
    throw new Error(`Unknown hooks type: ${type}`);
  }
}
