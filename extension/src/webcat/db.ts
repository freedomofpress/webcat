import { nonOrigins, origins } from "../globals"; // caching maps
import { logger } from "./logger";
import { extractHostname, extractRawHash } from "./parsers";

type StorageMode = "indexeddb" | "storage.local" | "memory";

export interface ListMetadata {
  hash: string;
  treeHead: number;
}

interface WebcatStorageBackend {
  settingsSet(key: string, value: number | string | bigint): Promise<void>;
  settingsGet<T>(key: string): Promise<T | null>;
  replaceList(leaves: readonly (readonly [string, string])[]): Promise<number>;
  getEnrollmentByFqdn(fqdn: string): Promise<Uint8Array>;
}

// Settings keys
const KEY_LAST_CHECKED = "lastChecked";
const KEY_LAST_UPDATED = "lastUpdated";
const KEY_ROOT_HASH = "rootHash";
const KEY_LAST_BLOCK_TIME = "lastBlockTime";
const KEY_LIST_COUNT = "listCount";

export class WebcatDatabase {
  private backendPromise: Promise<WebcatStorageBackend>;
  public readonly storageMode: StorageMode;

  constructor(private readonly name = "webcat") {
    const { backendPromise, storageMode } = this.createStorageBackend(
      this.name,
    );
    this.backendPromise = backendPromise;
    this.storageMode = storageMode;
  }

  private async getBackend(): Promise<WebcatStorageBackend> {
    return this.backendPromise;
  }

  private createStorageBackend(name: string): {
    backendPromise: Promise<WebcatStorageBackend>;
    storageMode: StorageMode;
  } {
    const backendPromise = this.tryIndexedDB(name)
      .then((backend) => {
        console.log("[webcat] Using IndexedDB backend");
        return { backend, mode: "indexeddb" as StorageMode };
      })
      .catch((e) => {
        console.warn("[webcat] IndexedDB unusable:", e);
        return this.tryBrowserStorage().then((backend) => {
          console.log("[webcat] Using browser.storage.local backend");
          return { backend, mode: "storage.local" as StorageMode };
        });
      })
      .catch((e) => {
        console.warn(
          "[webcat] browser.storage.local unusable, falling back to in-memory backend:",
          e,
        );
        return {
          backend: new InMemoryStorageBackend() as WebcatStorageBackend,
          mode: "memory" as StorageMode,
        };
      });

    backendPromise.then(({ mode }) => {
      (this as { storageMode: StorageMode }).storageMode = mode;
    });

    return {
      backendPromise: backendPromise.then(({ backend }) => backend),
      storageMode: "indexeddb", // optimistic default, updated above
    };
  }

  /** Try to open IndexedDB and verify it is writable (not read-only). */
  private async tryIndexedDB(name: string): Promise<WebcatStorageBackend> {
    if (typeof indexedDB === "undefined") {
      throw new Error("indexedDB is undefined");
    }

    const db = await this.openDatabase(name);

    // Probe: attempt a real write+delete to detect read-only mode (Tor Browser)
    await new Promise<void>((resolve, reject) => {
      try {
        const tx = db.transaction("settings", "readwrite");
        const store = tx.objectStore("settings");
        const req = store.put({ key: "__webcat_probe", value: 1 });
        req.onsuccess = () => {
          store.delete("__webcat_probe");
          resolve();
        };
        req.onerror = () => reject(new Error("IndexedDB write probe failed"));
        tx.onerror = () =>
          reject(new Error("IndexedDB write probe transaction failed"));
      } catch (e) {
        reject(e);
      }
    });

    return new IndexedDbStorageBackend(db);
  }

  /** Try to use browser.storage.local and verify it is writable. */
  private async tryBrowserStorage(): Promise<WebcatStorageBackend> {
    if (
      typeof browser === "undefined" ||
      !browser.storage ||
      !browser.storage.local
    ) {
      throw new Error("browser.storage.local is unavailable");
    }

    // Probe: verify we can actually write
    await browser.storage.local.set({ __webcat_probe: 1 });
    await browser.storage.local.remove("__webcat_probe");

    return new BrowserStorageBackend();
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

  async setLastChecked(): Promise<void> {
    const now = Date.now();
    const backend = await this.getBackend();
    await backend.settingsSet(KEY_LAST_CHECKED, now);
  }

  async getLastChecked(): Promise<number | null> {
    const backend = await this.getBackend();
    return backend.settingsGet<number>(KEY_LAST_CHECKED);
  }

  async setLastUpdated(): Promise<void> {
    const now = Date.now();
    const backend = await this.getBackend();
    await backend.settingsSet(KEY_LAST_UPDATED, now);
  }

  async getLastUpdated(): Promise<number | null> {
    const backend = await this.getBackend();
    return backend.settingsGet<number>(KEY_LAST_UPDATED);
  }

  async setRootHash(hash: string): Promise<void> {
    const backend = await this.getBackend();
    await backend.settingsSet(KEY_ROOT_HASH, hash);
  }

  async getRootHash(): Promise<string | null> {
    const backend = await this.getBackend();
    return backend.settingsGet<string>(KEY_ROOT_HASH);
  }

  async setLastBlockTime(seconds: bigint): Promise<void> {
    const backend = await this.getBackend();
    await backend.settingsSet(KEY_LAST_BLOCK_TIME, seconds);
  }

  async getLastBlockTime(): Promise<number | null> {
    const backend = await this.getBackend();
    return backend.settingsGet<number>(KEY_LAST_BLOCK_TIME);
  }

  async setListCount(count: number): Promise<void> {
    const backend = await this.getBackend();
    await backend.settingsSet(KEY_LIST_COUNT, count);
  }

  async getListCount(): Promise<number> {
    const backend = await this.getBackend();
    return (await backend.settingsGet<number>(KEY_LIST_COUNT)) ?? 0;
  }

  async updateList(
    leaves: readonly (readonly [string, string])[],
  ): Promise<void> {
    const backend = await this.getBackend();
    const processed = await backend.replaceList(leaves);

    // Clear caches after list update to prevent stale data usage
    origins.clear();
    nonOrigins.clear();

    await this.setListCount(processed);
    console.log(`[webcat] Replaced list with ${processed} leaves`);
  }

  async getFQDNEnrollment(fqdn: string): Promise<Uint8Array> {
    const backend = await this.getBackend();

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

    // 3. Storage backend lookup
    return backend.getEnrollmentByFqdn(fqdn);
  }
}

class IndexedDbStorageBackend implements WebcatStorageBackend {
  constructor(private readonly db: IDBDatabase) {}

  async settingsSet(
    key: string,
    value: number | string | bigint,
  ): Promise<void> {
    return new Promise((resolve, reject) => {
      const tx = this.db.transaction("settings", "readwrite");
      const st = tx.objectStore("settings");
      const req = st.put({ key, value });

      req.onsuccess = () => resolve();
      req.onerror = () => reject(new Error(`Failed to set ${key}`));
    });
  }

  async settingsGet<T>(key: string): Promise<T | null> {
    return new Promise((resolve, reject) => {
      const tx = this.db.transaction("settings", "readonly");
      const st = tx.objectStore("settings");
      const req = st.get(key);

      req.onsuccess = () => {
        if (!req.result) return resolve(null);
        resolve(req.result.value as T);
      };

      req.onerror = () => reject(new Error(`Failed to get ${key}`));
    });
  }

  async replaceList(
    leaves: readonly (readonly [string, string])[],
  ): Promise<number> {
    const tx = this.db.transaction("list", "readwrite");
    const store = tx.objectStore("list");

    await new Promise<void>((resolve, reject) => {
      const clearReq = store.clear();
      clearReq.onsuccess = () => resolve();
      clearReq.onerror = () =>
        reject(new Error("Failed to clear old list entries"));
    });

    const CHUNK_SIZE = 1000;
    let processed = 0;
    for (let i = 0; i < leaves.length; i += CHUNK_SIZE) {
      const chunk = leaves.slice(i, i + CHUNK_SIZE);
      for (const [reverseKey, hexHash] of chunk) {
        const hostname = extractHostname(reverseKey);
        const rawHash = extractRawHash(hexHash);
        store.add({ fqdn: hostname, policyhash: rawHash });
        processed++;
      }
    }

    await new Promise<void>((resolve, reject) => {
      tx.oncomplete = () => resolve();
      tx.onerror = () => reject(new Error("Transaction failed"));
    });

    return processed;
  }

  async getEnrollmentByFqdn(fqdn: string): Promise<Uint8Array> {
    return new Promise((resolve, reject) => {
      const tx = this.db.transaction("list", "readonly");
      const store = tx.objectStore("list");
      const index = store.index("fqdnIndex");
      const req = index.get(fqdn);

      req.onsuccess = () => {
        const result = req.result;
        if (result && result.policyhash) {
          resolve(new Uint8Array(result.policyhash));
        } else {
          nonOrigins.add(fqdn);
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

class BrowserStorageBackend implements WebcatStorageBackend {
  private readonly prefix = "webcat_";

  private key(k: string): string {
    return `${this.prefix}${k}`;
  }

  async settingsSet(
    key: string,
    value: number | string | bigint,
  ): Promise<void> {
    // bigint is not JSON-serializable, convert to string with a marker
    const stored =
      typeof value === "bigint"
        ? { __bigint: true, value: value.toString() }
        : value;
    await browser.storage.local.set({ [this.key(key)]: stored });
  }

  async settingsGet<T>(key: string): Promise<T | null> {
    const result = await browser.storage.local.get(this.key(key));
    const stored = result[this.key(key)];
    if (stored === undefined) return null;
    if (stored && typeof stored === "object" && stored.__bigint) {
      return BigInt(stored.value) as T;
    }
    return stored as T;
  }

  async replaceList(
    leaves: readonly (readonly [string, string])[],
  ): Promise<number> {
    // Remove old list entries
    const all = await browser.storage.local.get(null);
    const oldKeys = Object.keys(all).filter((k) =>
      k.startsWith(`${this.prefix}list_`),
    );
    if (oldKeys.length > 0) {
      await browser.storage.local.remove(oldKeys);
    }

    // Store new entries in chunks to avoid exceeding message size limits
    const CHUNK_SIZE = 500;
    let processed = 0;
    for (let i = 0; i < leaves.length; i += CHUNK_SIZE) {
      const chunk = leaves.slice(i, i + CHUNK_SIZE);
      const batch: Record<string, number[]> = {};
      for (const [reverseKey, hexHash] of chunk) {
        const hostname = extractHostname(reverseKey);
        const rawHash = extractRawHash(hexHash);
        batch[`${this.prefix}list_${hostname}`] = Array.from(rawHash);
        processed++;
      }
      await browser.storage.local.set(batch);
    }

    return processed;
  }

  async getEnrollmentByFqdn(fqdn: string): Promise<Uint8Array> {
    const key = `${this.prefix}list_${fqdn}`;
    const result = await browser.storage.local.get(key);
    const stored = result[key];
    if (stored) {
      return new Uint8Array(stored);
    }
    nonOrigins.add(fqdn);
    return new Uint8Array();
  }
}

class InMemoryStorageBackend implements WebcatStorageBackend {
  private readonly settings = new Map<string, number | string | bigint>();
  private readonly list = new Map<string, Uint8Array>();

  async settingsSet(
    key: string,
    value: number | string | bigint,
  ): Promise<void> {
    this.settings.set(key, value);
  }

  async settingsGet<T>(key: string): Promise<T | null> {
    const value = this.settings.get(key);
    return (value as T | undefined) ?? null;
  }

  async replaceList(
    leaves: readonly (readonly [string, string])[],
  ): Promise<number> {
    this.list.clear();
    for (const [reverseKey, hexHash] of leaves) {
      const hostname = extractHostname(reverseKey);
      const rawHash = extractRawHash(hexHash);
      this.list.set(hostname, new Uint8Array(rawHash));
    }
    return this.list.size;
  }

  async getEnrollmentByFqdn(fqdn: string): Promise<Uint8Array> {
    const result = this.list.get(fqdn);
    if (!result) {
      return new Uint8Array();
    }
    return new Uint8Array(result);
  }
}
