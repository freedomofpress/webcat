import contentHooks from "./../../dist/hooks/content.js?raw";
import pageHooks from "./../../dist/hooks/page.js?raw";
import { hooksType } from "./interfaces/base";

const hooks = {
  [hooksType.content_script]: contentHooks,
  [hooksType.page]: pageHooks,
};

export function getHooks(type: hooksType, wasm: string[], firstParty: string) {
  // This just patches the script string dynamically adding per-origin WASM hashes
  return hooks[type]
    .replace('"__ALLOWED_HASHES_PLACEHOLDER__"', JSON.stringify(wasm))
    .replace(
      '"__SHARED_WORKER_FIRST_PARTY_PLACEHOLDER__"',
      JSON.stringify(firstParty),
    )
    .replace(
      '"__SERVICE_WORKER_FIRST_PARTY_PLACEHOLDER__"',
      JSON.stringify(firstParty),
    );
}
