// src/mocks/db.mock.ts
export * from "../webcat/db";
import { WebcatDatabase as OriginalWebcatDatabase } from "../webcat/db";
import { hexToUint8Array } from "../webcat/encoding";

let list: Record<string, string> = {};
let listLoaded = false;

async function load() {
  const response = await fetch("http://127.0.0.1:1234/testing-list");
  list = (await response.json()) as Record<string, string>;
  listLoaded = true;
  console.log(
    `[TESTING] Loaded ${Object.keys(list).length} entries from testing list`,
  );
}

export class WebcatDatabase extends OriginalWebcatDatabase {
  async getFQDNEnrollment(fqdn: string): Promise<Uint8Array> {
    console.log("[TESTING] getFQDNEnrollment hooked for:", fqdn);

    // Wait for list to load if it hasn't yet
    if (!listLoaded) {
      await load();
    }

    const hexHash = list[fqdn];
    if (hexHash) {
      const hash = hexToUint8Array(hexHash);
      console.log(`[TESTING] Found enrollment for ${fqdn}:`, hexHash);
      return hash;
    }

    console.log(`[TESTING] No enrollment found for ${fqdn}`);
    return new Uint8Array();
  }
}

console.log("[TESTING] Mock db module loaded");
