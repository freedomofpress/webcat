import { nonOrigins, origins } from "../globals"; // caching maps
import { logger } from "./logger";
import { extractHostname, extractRawHash } from "./parsers";

export interface ListMetadata {
  hash: string;
  treeHead: number;
}

// Settings keys
const KEY_LAST_CHECKED = "lastChecked";
const KEY_LAST_UPDATED = "lastUpdated";
const KEY_ROOT_HASH = "rootHash";
const KEY_LAST_BLOCK_TIME = "lastBlockTime";
const KEY_LIST_COUNT = "listCount";

export class WebcatDatabase {
  private dbPromise: Promise<IDBDatabase>;

  constructor(private readonly name = "webcat") {
    this.dbPromise = this.openDatabase(this.name);
  }

  private async ensureDBOpen(): Promise<IDBDatabase> {
    return this.dbPromise;
  }

  private async openDatabase(name: string): Promise<IDBDatabase> {
    return new Promise((resolve, reject) => {
      const request = indexedDB.open(name, 1);

      request.onupgradeneeded = (event) => {
        const db = (event.target as IDBOpenDBRequest).result;

        try {
          const settings = db.createObjectStore("settings", { keyPath: "key" });
          settings.createIndex("settings", "key", { unique: true });

          const list = db.createObjectStore("list", { keyPath: "fqdn" });
          list.createIndex("fqdnIndex", "fqdn", { unique: true });

          console.log("[webcat] Created new list database");
        } catch (e) {
          reject(new Error(`Error creating object store: ${e}`));
        }
      };

      request.onsuccess = (event) => {
        const db = (event.target as IDBOpenDBRequest).result;
        console.log("[webcat] Database opened successfully");
        resolve(db);
      };

      request.onerror = (event) => {
        reject(
          new Error(
            `Error opening database: ${(event.target as IDBOpenDBRequest).error?.message}`,
          ),
        );
      };
    });
  }

  private async settingsSet(
    key: string,
    value: number | string | bigint,
  ): Promise<void> {
    const db = await this.ensureDBOpen();
    return new Promise((resolve, reject) => {
      const tx = db.transaction("settings", "readwrite");
      const st = tx.objectStore("settings");
      const req = st.put({ key, value });

      req.onsuccess = () => resolve();
      req.onerror = () => reject(new Error(`Failed to set ${key}`));
    });
  }

  private async settingsGet<T>(key: string): Promise<T | null> {
    const db = await this.ensureDBOpen();
    return new Promise((resolve, reject) => {
      const tx = db.transaction("settings", "readonly");
      const st = tx.objectStore("settings");
      const req = st.get(key);

      req.onsuccess = () => {
        if (!req.result) return resolve(null);
        resolve(req.result.value as T);
      };

      req.onerror = () => reject(new Error(`Failed to get ${key}`));
    });
  }

  async setLastChecked(): Promise<void> {
    const now = Date.now();
    await this.settingsSet(KEY_LAST_CHECKED, now);
  }

  async getLastChecked(): Promise<number | null> {
    return this.settingsGet<number>(KEY_LAST_CHECKED);
  }

  async setLastUpdated(): Promise<void> {
    const now = Date.now();
    await this.settingsSet(KEY_LAST_UPDATED, now);
  }

  async getLastUpdated(): Promise<number | null> {
    return this.settingsGet<number>(KEY_LAST_UPDATED);
  }

  async setRootHash(hash: string): Promise<void> {
    await this.settingsSet(KEY_ROOT_HASH, hash);
  }

  async getRootHash(): Promise<string | null> {
    return this.settingsGet<string>(KEY_ROOT_HASH);
  }

  async setLastBlockTime(seconds: bigint): Promise<void> {
    await this.settingsSet(KEY_LAST_BLOCK_TIME, seconds);
  }

  async getLastBlockTime(): Promise<number | null> {
    return this.settingsGet<number>(KEY_LAST_BLOCK_TIME);
  }

  async setListCount(count: number): Promise<void> {
    await this.settingsSet(KEY_LIST_COUNT, count);
  }

  async getListCount(): Promise<number> {
    return (await this.settingsGet<number>(KEY_LIST_COUNT)) ?? 0;
  }

  async updateList(
    leaves: readonly (readonly [string, string])[],
  ): Promise<void> {
    const db = await this.ensureDBOpen();
    const tx = db.transaction("list", "readwrite");
    const store = tx.objectStore("list");

    // 1. Remove existing entries (replace-only mode)
    await new Promise<void>((resolve, reject) => {
      const clearReq = store.clear();
      clearReq.onsuccess = () => resolve();
      clearReq.onerror = () =>
        reject(new Error("Failed to clear old list entries"));
    });

    // 2. Insert new leaves
    const CHUNK_SIZE = 1000;
    let processed = 0;

    for (let i = 0; i < leaves.length; i += CHUNK_SIZE) {
      const chunk = leaves.slice(i, i + CHUNK_SIZE);

      for (const [reverseKey, hexHash] of chunk) {
        const hostname = extractHostname(reverseKey);
        const rawHash = extractRawHash(hexHash);

        store.add({
          fqdn: hostname,
          policyhash: rawHash,
        });

        processed++;
      }
    }

    // 3. Update stored count
    await new Promise<void>((resolve, reject) => {
      tx.oncomplete = () => resolve();
      tx.onerror = () => reject(new Error("Transaction failed"));
    });
    await this.setListCount(processed);
    console.log(`[webcat] Replaced list with ${processed} leaves`);
  }

  async getFQDNEnrollment(fqdn: string): Promise<Uint8Array> {
    const db = await this.ensureDBOpen();

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

    // 3. IndexedDB lookup
    return new Promise((resolve, reject) => {
      const tx = db.transaction("list", "readonly");
      const store = tx.objectStore("list");
      const index = store.index("fqdnIndex");

      const req = index.get(fqdn);

      req.onsuccess = () => {
        const result = req.result;

        if (result && result.policyhash) {
          resolve(new Uint8Array(result.policyhash));
        } else {
          nonOrigins.add(fqdn); // cache miss
          resolve(new Uint8Array());
        }
      };

      req.onerror = () => {
        logger.addLog(
          "error",
          `Error fetching local database for enrollment, fqdn = ${fqdn}`,
          -1,
          fqdn,
        );
        reject(new Uint8Array());
      };
    });
  }
}
