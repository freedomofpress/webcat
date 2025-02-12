import hooksCode from "./../../dist/hooks.js?raw";

export function getHooks(wasm: string[]) {
  // This just patches the script string dynamically adding per-origin WASM hashes
  return hooksCode.replace('["__HASHES_PLACEHOLDER__"]', JSON.stringify(wasm));
}
