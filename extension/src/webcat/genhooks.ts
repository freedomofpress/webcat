import contentHooks from "./../../dist/hooks/content.js?raw";
import pageHooks from "./../../dist/hooks/page.js?raw";
import { hooksType } from "./interfaces/base";

export function getHooks(type: hooksType, wasm: string[], key: string) {
  // This just patches the script string dynamically adding per-origin WASM hashes
  if (type === hooksType.page) {
    return pageHooks
      .replace('["__HASHES_PLACEHOLDER__"]', JSON.stringify(wasm))
      .replace("__KEY_PLACEHOLDER__", key);
  } else if (type === hooksType.content_script) {
    return contentHooks
      .replace('["__HASHES_PLACEHOLDER__"]', JSON.stringify(wasm))
      .replace("__KEY_PLACEHOLDER__", key);
  } else {
    throw new Error(`Unknown hooks type: ${type}`);
  }
}
