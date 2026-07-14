import { firstPartyKey, firtsPartySalt as firstPartySalt } from "../globals";
import contentHooks from "./../../dist/hooks/content.js?raw";
import pageHooks from "./../../dist/hooks/page.js?raw";
import { hooksType } from "./interfaces/base";

const hooks = {
  [hooksType.content_script]: contentHooks,
  [hooksType.page]: pageHooks,
};

// This just patches the script string dynamically,
// adding per-origin WASM hashes and FPO hints
export async function getHooks(
  type: hooksType,
  wasm: string[],
  firstParty: string,
  sameOrigin: boolean,
) {
  // Generate deterministic IV using HKDF and SHA-256. Using firstParty as the input
  // ensures the same IV is never used for encrypting two different plaintext. Using
  // firstPartySalt instead of the default zero salt ensures an attacker can't generate
  // collisions.
  const iv = await crypto.subtle.deriveBits(
    {
      name: "HKDF",
      hash: "SHA-256",
      salt: firstPartySalt,
      info: new ArrayBuffer(),
    },
    await crypto.subtle.importKey(
      "raw",
      new TextEncoder().encode(firstParty),
      { name: "HKDF" },
      false,
      ["deriveBits"],
    ),
    96,
  );
  // Encrypt firstParty
  const ct = new Uint8Array(
    await crypto.subtle.encrypt(
      { name: "AES-GCM", iv },
      await firstPartyKey,
      new TextEncoder().encode(firstParty),
    ),
  );
  // Construct the first party URL fragment value
  const efpo = new Uint8Array(iv.byteLength + ct.byteLength);
  efpo.set(new Uint8Array(iv));
  efpo.set(ct, iv.byteLength);
  const efpoBase64 = efpo.toBase64({ alphabet: "base64url" });
  // Return the hook script updated with data
  return hooks[type].replace(
    '"__DATA_PLACEHOLDER__"',
    JSON.stringify({
      hashes: wasm,
      firstParty: efpoBase64,
      sameOriginWithFirstParty: sameOrigin,
    }),
  );
}
