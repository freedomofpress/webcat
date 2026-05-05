import { nonOrigins, origins } from "../globals"; // caching maps
import { extractHostname, extractRawHash } from "./parsers";

const META_KEY = "block_meta";

export interface BlockMeta {
  blockTime: number;
  rootHash: string;
}

export class WebcatDatabase {
  async updateList(
    leaves: readonly (readonly [string, string])[],
    meta: BlockMeta,
  ): Promise<void> {
    await browser.storage.local.clear();

    const batch: Record<string, unknown> = {};
    for (const [reverseKey, hexHash] of leaves) {
      const hostname = extractHostname(reverseKey);
      const rawHash = extractRawHash(hexHash);
      batch[hostname] = Array.from(rawHash);
    }
    batch[META_KEY] = meta;

    await browser.storage.local.set(batch);

    origins.clear();
    nonOrigins.clear();

    console.log(`[webcat] Replaced list with ${leaves.length} entries`);
  }

  async getBlockMeta(): Promise<BlockMeta | null> {
    const result = await browser.storage.local.get(META_KEY);
    return (result[META_KEY] as BlockMeta) ?? null;
  }

  async listAllFQDNs(): Promise<string[]> {
    const all = await browser.storage.local.get(null);
    return Object.keys(all).filter((k) => k !== META_KEY);
  }

  async getFQDNEnrollment(fqdn: string): Promise<Uint8Array> {
    // 1. Positive-cache hit
    const originState = origins.get(fqdn);
    if (originState) {
      const cached = originState.current.enrollment_hash;
      if (!cached) {
        throw new Error(
          "FATAL: cached origin exists without an enrollment_hash",
        );
      }
      return cached;
    }

    // 2. Negative-cache hit
    if (nonOrigins.has(fqdn)) {
      return new Uint8Array();
    }

    // 3. Storage lookup
    const result = await browser.storage.local.get(fqdn);
    const stored = result[fqdn];
    if (stored) {
      return new Uint8Array(stored);
    } else {
      nonOrigins.add(fqdn);
      return new Uint8Array();
    }
  }

  async setLastChecked(): Promise<void> {
    await browser.storage.session.set({ lastChecked: Date.now() });
  }

  async getLastChecked(): Promise<number | null> {
    const result = await browser.storage.session.get("lastChecked");
    return result.lastChecked ?? null;
  }

  async setLastUpdated(): Promise<void> {
    await browser.storage.session.set({ lastUpdated: Date.now() });
  }

  async getLastUpdated(): Promise<number | null> {
    const result = await browser.storage.session.get("lastUpdated");
    return result.lastUpdated ?? null;
  }
}
