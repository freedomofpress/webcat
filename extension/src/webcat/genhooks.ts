import contentHooks from "./../../dist/hooks/content.js?raw";
import pageHooks from "./../../dist/hooks/page.js?raw";
import { hooksType } from "./interfaces/base";

export function getHooks(type: hooksType, wasm: string[]) {
  // This just patches the script string dynamically adding per-origin WASM hashes
  if (type === hooksType.page) {
    return pageHooks.replace(
      '["__HASHES_PLACEHOLDER__"]',
      JSON.stringify(wasm),
    );
  } else if (type === hooksType.content_script) {
    return contentHooks.replace(
      '["__HASHES_PLACEHOLDER__"]',
      JSON.stringify(wasm),
    );
  } else {
    throw new Error(`Unknown hooks type: ${type}`);
  }
}
