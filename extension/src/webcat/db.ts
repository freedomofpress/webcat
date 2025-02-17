import { nonOrigins, origins } from "./../globals";
import { logger } from "./logger";
import { SHA256 } from "./utils";

export let list_count: number = 0;
let list_db: IDBDatabase;

// https://stackoverflow.com/questions/40593260/should-i-open-an-idbdatabase-each-time-or-keep-one-instance-open
// Someone here claims opening and close is almost the same as keeping it open, performance-wise
// But it is also true that most reccomendations suggest to do that for apps that do multiple operations
// We just do lookups... Worth investigating performance/best practices later

export async function ensureDBOpen() {
  if (!list_db) {
    list_db = await openDatabase("webcat");
  }
}

export async function openDatabase(db_name: string): Promise<IDBDatabase> {
  return new Promise((resolve, reject) => {
    const request = indexedDB.open(db_name, 1);

    // At the moment we are using this event only to detect if the db doesnt exists. We do not handle
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
        initDatabase(db);

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

export async function initDatabase(db: IDBDatabase) {
  // Fetch the raw bytes file from the browser extension's assets
  const response = await fetch(browser.runtime.getURL("assets/dev_list.bin"));

  if (!response.ok) {
    throw new Error(`Failed to load binary file: ${response.statusText}`);
  }

  const rawBytes = new Uint8Array(await response.arrayBuffer());

  // Insert the binary data into the database
  await insertBinaryData(db, rawBytes);

  const randomCount = 1000;
  const randomBytes = new Uint8Array(64 * randomCount);
  crypto.getRandomValues(randomBytes);
  await insertBinaryData(db, randomBytes);
  list_count = await getCount("list");
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

export async function getFQDNPolicy(fqdn: string): Promise<Uint8Array> {
  // Caching of hits
  await ensureDBOpen();
  const originStateHolder = origins.get(fqdn);
  if (originStateHolder) {
    // This can't happen AFAIK
    if (!originStateHolder.current.policy_hash) {
      throw new Error(
        "FATAL: we found a cached origin without a policy associated",
      );
    }
    //logger.addLog("debug", `Policy cache hit for ${fqdn}`, -1, fqdn);

    return originStateHolder.current.policy_hash;
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
