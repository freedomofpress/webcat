import { hexToUint8Array } from "../sigstore/encoding";
import { list_db, origins } from "./listeners";
import { logger } from "./logger";
import { arrayBufferToHex, SHA256 } from "./utils";

type ListElement = [ArrayBuffer, Uint8Array];
type SettingElement = [string, string | number | Date];

// https://stackoverflow.com/questions/40593260/should-i-open-an-idbdatabase-each-time-or-keep-one-instance-open
// Someone here claims opening and close is almost the same as keeping it open, performance-wise
// But it is also true that most reccomendations suggest to do that for apps that do multiple operations
// We just do lookups... Worth investigating performance/best practices later

// Let's keep this for now but it's better to just use the built-in upgrade events
export async function databaseExists(database_name: string) {
  const databases = await indexedDB.databases();
  if (databases.map((db) => db.name).includes(database_name)) {
    return true;
  } else {
    return false;
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
        //db.objectStoreNames.contains(""));
        // Create stores and corresponding indexes; in neither there should be duplicates
        const settingstore = db.createObjectStore("settings", {
          keyPath: "key",
        });
        settingstore.createIndex("settings", "key", { unique: true });
        const liststore = db.createObjectStore("list", { keyPath: "fqdnhash" });
        liststore.createIndex("list", "fqdnhash", { unique: true });

        console.log("[webcat]", "Created new list database");

        console.log("[webcat]", "Populated new database");
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

// This interface is pretty ugly, TODO rethink better
async function dbBulkAdd(
  db: IDBDatabase,
  storename: string,
  data: ListElement[] | SettingElement[],
  keyname: string,
  valuename: string,
): Promise<boolean> {
  return new Promise((resolve, reject) => {
    const transaction = db.transaction(storename, "readwrite");
    const store = transaction.objectStore(storename);

    for (const item of data) {
      store.add({ [keyname]: item[0], [valuename]: item[1] });
    }

    transaction.oncomplete = () => resolve(true);
    transaction.onerror = (event) => {
      console.error("BulkAdd failed", event);
      reject(false);
    };
  });
}

export async function initDatabase(db: IDBDatabase) {
  // Ideally here we would fetch the list remotelym verify signature and inclusion proof
  // and maybe freshness, if we do not delegate that to TUF
  const listElements: ListElement[] = [
    [
      await SHA256("lsd.cat"),
      hexToUint8Array(
        "d6c9bee32f85ff71162afd1daa5ce876fd442af4105a08fbd70aa7291ab90ba0",
      ),
    ],
    [
      await SHA256("nym.re"),
      hexToUint8Array(
        "d6c9bee32f85ff71162afd1daa5ce876fd442af4105a08fbd70aa7291ab90ba0",
      ),
    ],
    [
      await SHA256("globaleaks.nym.re"),
      hexToUint8Array(
        "02e17c9ff4b43edeff9abc3aada626dcf3488ffd5f566e7c6c24818d8490c26c",
      ),
    ],
    [
      await SHA256("element.nym.re"),
      hexToUint8Array(
        "68f09b59bff0c8642de468a643ee45cd8e60441239b8f6f0797e0af465156526",
      ),
    ],
    [
      await SHA256("jitsi.nym.re"),
      hexToUint8Array(
        "6b4b6402a364cdde80f7d54f34939e57e1b6fb94ad489f96d8787eb60fd1bfbe",
      ),
    ],
    [
      await SHA256("a.nym.re"),
      hexToUint8Array(
        "dd0e0562d6130566757cc3512efd425380baf25fa0086346a511fa277202c49f",
      ),
    ],
    [
      await SHA256("b.nym.re"),
      hexToUint8Array(
        "c0eac7fc18d8b1b3dcba8d48e0468f67e533d013cc24f83ec79828626239392f",
      ),
    ],
    [
      await SHA256("cryptpad.nym.re"),
      hexToUint8Array(
        "b96b4939a3507be18ddcc799f7fc2b37f1acafcbb0734e90d3703259f57b4579",
      ),
    ],
    [
      await SHA256("sandbox.cryptpad.nym.re"),
      hexToUint8Array(
        "b96b4939a3507be18ddcc799f7fc2b37f1acafcbb0734e90d3703259f57b4579",
      ),
    ],
    [
      await SHA256("bitwarden.nym.re"),
      hexToUint8Array(
        "6e17ccb0d244a5cfaaf8e878a430010c83f81b5fef3ad83394155c43b7702213",
      ),
    ],
  ];

  const settingElements: SettingElement[] = [
    ["version", 1],
    ["last_update", Date.now()],
  ];

  // Here we attempt a bulk insert, and to do everything in a single transaction
  // for large numbers of insert, it could be that batching (such as 10k chunks) could be beneficial
  dbBulkAdd(db, "list", listElements, "fqdnhash", "policyhash");
  dbBulkAdd(db, "settings", settingElements, "key", "value");
}

// TabID is passed only mostly for debugging
export async function isFQDNEnrolled(
  fqdn: string,
  tabId: number,
): Promise<boolean | Uint8Array> {
  if (origins.has(fqdn)) {
    if (!origins.get(fqdn)?.policyHash) {
      throw new Error(
        "FATAL: we found a cached origin without a policy associated",
      );
    }
    logger.addLog("info", `Policy cache hit for ${fqdn}`, tabId, fqdn);
    return origins.get(fqdn)!.policyHash;
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
        logger.addLog(
          "info",
          `Found policy hash ${arrayBufferToHex(request.result["policyhash"])} for ${fqdn}`,
          tabId,
          fqdn,
        );
        resolve(new Uint8Array(request.result["policyhash"]));
      } else {
        resolve(false);
      }
    };
    request.onerror = () => {
      logger.addLog(
        "error",
        `Error fetching local database for enrollment, fqdn = ${fqdn}`,
        -1,
        fqdn,
      );
      reject(false);
    };
  });
}
