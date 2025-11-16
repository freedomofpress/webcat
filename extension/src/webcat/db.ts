import { nonOrigins, origins } from "./../globals";
import { hexToUint8Array } from "./encoding";
import { logger } from "./logger";
import { SHA256 } from "./utils";

export let list_count: number;
export let list_db: IDBDatabase;
export let list_last_checked: number;
export let list_version: string;

declare const __TESTING__: boolean;

// https://stackoverflow.com/questions/40593260/should-i-open-an-idbdatabase-each-time-or-keep-one-instance-open
// Someone here claims opening and close is almost the same as keeping it open, performance-wise
// But it is also true that most recommendations suggest to do that for apps that do multiple operations
// We just do lookups... Worth investigating performance/best practices later

export async function ensureDBOpen() {
  if (!list_db) {
    list_db = await openDatabase("webcat");
  }
}

export async function openDatabase(db_name: string): Promise<IDBDatabase> {
  return new Promise((resolve, reject) => {
    const request = indexedDB.open(db_name, 1);

    // At the moment we are using this event only to detect if the db doesn't exists. We do not handle
    // any kind of migrations yet
    request.onupgradeneeded = (event: IDBVersionChangeEvent) => {
      const db = (event.target as IDBOpenDBRequest).result;

      try {
        // Create stores and corresponding indexes; in neither there should be duplicates
        const settingstore = db.createObjectStore("settings", {
          keyPath: "key",
        });
        settingstore.createIndex("settings", "key", { unique: true });
        const liststore = db.createObjectStore("list", { keyPath: "fqdnhash" });
        liststore.createIndex("list", "fqdnhash", { unique: true });

        console.log("[webcat]", "Created new list database");
      } catch (error) {
        reject(new Error(`Error creating object store: ${error}`));
      }
    };

    request.onsuccess = (event) => {
      const db = (event.target as IDBOpenDBRequest).result;
      console.log("[webcat]", "Database opened successfully.");
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

export async function updateLastChecked(db: IDBDatabase): Promise<void> {
  list_count = await getCount("list");
  return new Promise((resolve, reject) => {
    const transaction = db.transaction("settings", "readwrite");
    const store = transaction.objectStore("settings");
    const now = Date.now();
    list_last_checked = now;
    const record = { key: "lastChecked", timestamp: now };
    const request = store.put(record);
    request.onsuccess = () => {
      console.log("[webcat] Last checked timestamp updated:", now);
      resolve();
    };
    request.onerror = () => {
      reject(new Error("Failed to update lastChecked timestamp"));
    };
  });
}

export async function getLastChecked(db: IDBDatabase): Promise<number | null> {
  return new Promise((resolve, reject) => {
    const transaction = db.transaction("settings", "readonly");
    const store = transaction.objectStore("settings");
    const request = store.get("lastChecked");
    request.onsuccess = () => {
      if (request.result && request.result.timestamp) {
        resolve(request.result.timestamp);
      } else {
        resolve(null);
      }
    };
    request.onerror = () => {
      reject(new Error("Failed to retrieve lastChecked timestamp"));
    };
  });
}

export interface ListMetadata {
  hash: string;
  treeHead: number;
}

export async function getListMetadata(
  db: IDBDatabase,
): Promise<ListMetadata | null> {
  return new Promise((resolve, reject) => {
    const transaction = db.transaction("settings", "readonly");
    const store = transaction.objectStore("settings");
    const request = store.get("listMetadata");
    request.onsuccess = () => {
      if (request.result) {
        list_version = request.result.hash;
      }
      resolve(request.result || null);
    };
    request.onerror = () => {
      reject(new Error("Failed to get list metadata"));
    };
  });
}

export async function updateListMetadata(
  db: IDBDatabase,
  hash: string,
  treeHead: number,
): Promise<void> {
  return new Promise((resolve, reject) => {
    const transaction = db.transaction("settings", "readwrite");
    const store = transaction.objectStore("settings");
    list_version = hash;
    const metadata = { key: "listMetadata", hash, treeHead };
    const request = store.put(metadata);
    request.onsuccess = () => resolve();
    request.onerror = () => reject(new Error("Failed to update list metadata"));
  });
}

export async function reinitializeDatabase(
  db: IDBDatabase,
  rawBytes: Uint8Array,
  newHash: string,
  newTreeHead: number,
): Promise<void> {
  return new Promise((resolve, reject) => {
    const transaction = db.transaction(["list", "settings"], "readwrite");
    const listStore = transaction.objectStore("list");
    // First clear the existing list entries.
    const clearRequest = listStore.clear();
    clearRequest.onsuccess = async () => {
      try {
        // Insert new binary data into "list"
        await insertBinaryData(db, rawBytes);
        // Update the metadata in "settings"
        await updateListMetadata(db, newHash, newTreeHead);
        resolve();
      } catch (err) {
        reject(err);
      }
    };
    clearRequest.onerror = () => {
      reject(new Error("Failed to clear list store"));
    };
  });
}

export async function updateDatabase(
  db: IDBDatabase,
  newHash: string,
  newTreeHead: number,
  rawBytes: Uint8Array,
): Promise<void> {
  // Check if the "list" store is empty.

  if (__TESTING__) {
    console.log("[webcat] Running test list insertion.");
    // Block used for local testing; by using a define, it should be a dead branch and compiled out
    const numRandom = 1000;
    const rawBytes = new Uint8Array(64);
    const encoder = new TextEncoder();

    const staticPolicy = hexToUint8Array(
      "77f407ed38cdb1c8ad44839fa33b491c0eb93bd2f46afdf3071a62be933ea22a",
    ); // Replace if needed

    const ip = `127.0.0.1`;
    const fqdnHash = new Uint8Array(await SHA256(encoder.encode(ip)));
    rawBytes.set(fqdnHash, 0);
    rawBytes.set(staticPolicy, 32);

    await insertBinaryData(db, rawBytes);

    console.log(`[webcat] Inserted localhost test entry.`);

    const randomBytes = new Uint8Array(64 * numRandom);
    crypto.getRandomValues(randomBytes);
    await insertBinaryData(db, randomBytes);
    await updateListMetadata(
      db,
      "deadbeefdeadbeefdeadbeefdeadbeefdeadbeefdeadbeefdeadbeefdeadbeef",
      1337,
    );

    console.log(`[webcat] Inserted ${numRandom} random entries.`);
  } else {
    console.log("[webcat] Running production list insertion.");
    // "Production"
    const count = await getCount("list");

    if (count === 0) {
      // No data present: perform initial insertion.
      await insertBinaryData(db, rawBytes);
      await updateListMetadata(db, newHash, newTreeHead);
      console.log("[webcat] Database initialized with new binary update list.");
    } else {
      // Data already exists: reinitialize the store.
      await reinitializeDatabase(db, rawBytes, newHash, newTreeHead);
      console.log("[webcat] Database updated with new binary update list.");
    }
  }
  // Update the "lastChecked" timestamp.
  await updateLastChecked(db);
}

// Quest for performance in inserts, see https://stackoverflow.com/questions/22247614/optimized-bulk-chunk-upload-of-objects-into-indexeddb
// In general consider that IDB is more efficient for queries, which makes sense for our use case
// But making the first insert reasonably performant is still worth
// https://github.com/dexie/Dexie.js/blob/216ec560d09fb259413374b66754dbc97bc79a15/src/classes/table/table.ts#L441
// https://blog.lekoala.be/indexeddb-bulk-inserts-are-slow

// We have just one type of data, sha256 hases in their raw format
// Thus any file format is just overhead, both in term of space and parsing.

export async function insertBinaryData(db: IDBDatabase, rawBytes: Uint8Array) {
  // Configure chunk size for bulk insertion
  const CHUNK_SIZE = 1000;

  // Open a transaction for bulk insertion
  const transaction = db.transaction("list", "readwrite");
  const store = transaction.objectStore("list");

  for (let i = 0; i < rawBytes.length; i += 64 * CHUNK_SIZE) {
    const chunkEnd = Math.min(rawBytes.length, i + 64 * CHUNK_SIZE);

    for (let j = i; j < chunkEnd; j += 64) {
      const fqdn = rawBytes.slice(j, j + 32);
      const policy = rawBytes.slice(j + 32, j + 64);

      store.add({
        fqdnhash: fqdn,
        policyhash: policy,
      });
    }
  }

  transaction.oncomplete = () => {
    console.log("[webcat] Bulk insert completed successfully.");
  };

  transaction.onerror = (event) => {
    console.error(
      "[webcat] Bulk insert failed",
      (event.target as IDBTransaction).error?.message,
    );
  };
}

// To be used in the UI
export async function getCount(storeName: string): Promise<number> {
  await ensureDBOpen();
  return new Promise((resolve, reject) => {
    const transaction = list_db.transaction(storeName, "readonly");
    const store = transaction.objectStore(storeName);
    const countRequest = store.count();

    countRequest.onsuccess = () => {
      resolve(countRequest.result);
    };

    countRequest.onerror = () => {
      reject(new Error(`Failed to count elements in ${storeName}`));
    };
  });
}

export async function getFQDNEnrollment(fqdn: string): Promise<Uint8Array> {
  // Caching of hits
  await ensureDBOpen();
  const originStateHolder = origins.get(fqdn);
  if (originStateHolder) {
    // This can't happen AFAIK
    if (!originStateHolder.current.enrollment_hash) {
      throw new Error(
        "FATAL: we found a cached origin without a policy associated",
      );
    }
    //logger.addLog("debug", `Policy cache hit for ${fqdn}`, -1, fqdn);

    return originStateHolder.current.enrollment_hash;
  }

  // Caching of misses
  if (nonOrigins.has(fqdn)) {
    //logger.addLog("info", `Non enrolled cache hit for ${fqdn}`, -1, fqdn);
    return new Uint8Array();
  }

  const fqdn_hash = await SHA256(fqdn);
  //console.log(`Checking ${fqdn}, hash = ${arrayBufferToHex(fqdn_hash)}`)
  return new Promise((resolve, reject) => {
    const transaction = list_db.transaction("list", "readonly");
    const store = transaction.objectStore("list");
    const index = store.index("list");
    const request = index.get(fqdn_hash);

    request.onsuccess = () => {
      if (request.result && request.result["policyhash"]) {
        //logger.addLog(
        //  "info",
        //  `Found policy hash ${arrayBufferToHex(request.result["policyhash"])} for ${fqdn}`,
        //  -1,
        //  fqdn,
        //);
        resolve(new Uint8Array(request.result["policyhash"]));
      } else {
        // Insert in cache
        //logger.addLog("debug", `${fqdn} non-enrolled, caching`, -1, fqdn);
        nonOrigins.add(fqdn);
        resolve(new Uint8Array());
      }
    };
    request.onerror = () => {
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
