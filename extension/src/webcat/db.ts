import { hexToUint8Array } from '../sigstore/encoding';
import { logger } from './logger';
import { SHA256, arrayBufferToHex, getFQDN } from "./utils";
import { OriginState } from './interfaces';

// https://stackoverflow.com/questions/40593260/should-i-open-an-idbdatabase-each-time-or-keep-one-instance-open
// Someone here claims opening and close is almost the same as keeping it open, performance-wise
// But it is also true that most reccomendations suggest to do that for apps that do multiple operations
// We just do lookups... Worth investigating performance/best practices later

// Let's keep this for now but it's better to just use the built-in upgrade events
export async function databaseExists(database_name: string) {
    const databases = await indexedDB.databases();
    if (databases.map(db => db.name).includes(database_name)) {
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
                const settingstore = db.createObjectStore("settings", { keyPath: "key" });
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
            reject(new Error(`Error opening database: ${(event.target as IDBOpenDBRequest).error?.message}`));
        };
    });
}

// Quest for performance in inserts, see https://stackoverflow.com/questions/22247614/optimized-bulk-chunk-upload-of-objects-into-indexeddb
// In general consider that IDB is more efficient for queries, which makes sense for our use case
// But making the first insert reasonably performant is still worth
// https://github.com/dexie/Dexie.js/blob/216ec560d09fb259413374b66754dbc97bc79a15/src/classes/table/table.ts#L441
// https://blog.lekoala.be/indexeddb-bulk-inserts-are-slow

// This interface is pretty ugly, TODO rethink better
async function dbBulkAdd(db: IDBDatabase, storename: string, data: Array<Array<any>>, keyname: string, valuename: string): Promise<boolean> {
    return new Promise((resolve, reject) => {
        const transaction = db.transaction(storename, "readwrite");
        const store = transaction.objectStore(storename);

        for (const item of data) {
            store.add({[keyname]: item[0], [valuename]: item[1]});
        }

        transaction.oncomplete = () => resolve(true);
        transaction.onerror = (event) => {
            console.error("BulkAdd failed");
            reject(false);
        }
    });
}

export async function initDatabase(db: IDBDatabase) {
    // Ideally here we would fetch the list remotelym verify signature and inclusion proof
    // and maybe freshness, if we do not delegate that to TUF
    const listElements = [
        [await SHA256("lsd.cat"), await SHA256("policy1")],
        [await SHA256("nym.re"), hexToUint8Array("d6c9bee32f85ff71162afd1daa5ce876fd442af4105a08fbd70aa7291ab90ba0")],
        [await SHA256("globaleaks.nym.re"), hexToUint8Array("17d1f9b10f534d0b256174aea048bcb0b57cf2b9f907e0b3e8ce3b00615a58f4")], 
        [await SHA256("element.nym.re"), hexToUint8Array("a8553696f549d32ed01b1664423ea8adbe468c55557eaf6436cb143a1ad754fd")],
        [await SHA256("jitsi.nym.re"), hexToUint8Array("6b4b6402a364cdde80f7d54f34939e57e1b6fb94ad489f96d8787eb60fd1bfbe")]
    ]

    const settingElements = [
        ["version", 1],
        ["last_update", Date.now()]
    ]

    // Here we attempt a bulk insert, and to do everything in a single transaction
    // for large numbers of insert, it could be that batching (such as 10k chunks) could be beneficial
    dbBulkAdd(db, "list", listElements, "fqdnhash", "policyhash");
    dbBulkAdd(db, "settings", settingElements, "key", "value");
}

// TabID is passed only mostly for debugging
export async function isFQDNEnrolled(db: IDBDatabase, fqdn: string, origins: Map<string, OriginState>, tabId: number): Promise<boolean|Uint8Array> {
    if (origins.has(fqdn)) {
        if (!origins.get(fqdn)?.policyHash) {
            throw new Error("FATAL: we found a cached origin without a policy associated");
        }
        logger.addLog("info", `Policy cache hit for ${fqdn}`, tabId, fqdn)
        return origins.get(fqdn)!.policyHash;
    }

    const fqdn_hash = await SHA256(fqdn);
    //console.log(`Checking ${fqdn}, hash = ${arrayBufferToHex(fqdn_hash)}`)
    return new Promise((resolve, reject) => {
        const transaction = db.transaction("list", "readonly");
        const store = transaction.objectStore("list");
        const index = store.index("list");
        const request = index.get(fqdn_hash);

        request.onsuccess = () => {
            if (request.result && request.result["policyhash"]) {
                logger.addLog("info", `Found policy hash ${arrayBufferToHex(request.result["policyhash"])} for ${fqdn}`, tabId, fqdn)
                resolve(new Uint8Array(request.result["policyhash"]));
            } else {
                resolve(false);
            }
        };
        request.onerror = () => {
            logger.addLog("error", `Error fetching local database for enrollment, fqdn = ${fqdn}`, -1, fqdn)
            reject(false);
        };
    });
}