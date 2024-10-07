import { loadKeys, checkSignatures } from "./crypto";
import { Metafile, Root, Roles } from "./interfaces";

const TUF_REPOSITORY_URL = "https://tuf-repo-cdn.sigstore.dev";
const STARTING_ROOT_PATH = "assets/1.root.json";

// Listeners
browser.runtime.onInstalled.addListener(installListener);

// Let's keep it simple for now and deal with abstractions later

async function fetchMetafile(version: number, role: string): Promise<any> {
    const url = `${TUF_REPOSITORY_URL}/${version}.${role}.json`;
  
    console.log("Fetching ", url)
    try {
        const response = await fetch(url);
  
        if (!response.ok) {
            throw new Error(`Failed to fetch file: ${response.status} ${response.statusText}`);
        }

        const json = await response.json();
      
        return json;
    } catch (error) {
        throw new Error(`Error fetching TUF file: ${error}`);
    }
}

async function openBootstrapRoot(file: string): Promise<any> {
    try {
        const response = await fetch(browser.runtime.getURL(file));
        const json = await response.json();

        return json;
    } catch (error) {
        throw new Error(`Failed to load the JSON file:  ${error}`);
    }
}

// This function supports ECDSA (256, 385, 521), Ed25519 in Hex or PEM format
// it is possible to support certain cases of RSA, but it is not really useful for now
// Returns a mapping keyd (hexstring) -> CryptoKey object
async function loadRoot(json: Metafile, oldroot?: Root): Promise<Root> {

    if (json.signed._type !== "root") {
        throw new Error("Loading the wrong metafile as root.");
    }

    var keys: Map<string, CryptoKey>;
    var threshold: number;

    // If no oldroot, this is a fresh start froma trusted file, so it's self signed
    if (oldroot == undefined) {
        keys = await loadKeys(json.signed.keys);
        // We want to check everybody signed the bootstrap file
        threshold = 0;
    } else {
        keys = oldroot.keys;
        // We should respect the previous threshold, otherwise it does not make sense
        threshold = oldroot.threshold;
    }

    if (await checkSignatures(keys, json.signed, json.signatures, threshold) !== true) {
        throw new Error("Failed to verify metafile.");
    }

    // If we are loading a new root, let's load the new keys since we have verified them
    if (oldroot != undefined) {
        keys = await loadKeys(json.signed.keys);
    }

    if (!Number.isSafeInteger(json.signed.version) || json.signed.version < 1) {
        throw new Error("There is something wrong with the root version number.");
    }

    return {
        keys: keys,
        version: json.signed.version,
        expires: new Date(json.signed.expires),
        threshold: json.signed.roles.root.threshold
    };
}


async function updateRoot() {
    const rootJson = await openBootstrapRoot(STARTING_ROOT_PATH);
    const freeze_date = new Date();
    var root = await loadRoot(rootJson);
    var newroot: Root = root;

    // In theory max version is the maximum integer size, probably 2^32 per the spec, in practice this should be safe for a century
    for (var new_version = root.version + 1; new_version < 8192; new_version++) {

        console.log("Loading new root");
        console.log("current root version ", root.version)
        console.log("current root threshold ", root.threshold)
        try {
            var newrootJson = await fetchMetafile(new_version, Roles.Root);
        } catch {
            // Fetching failed and we assume there is no new version
            // Maybe we should explicitly check for 404 failures
            // Cause a network failure may be an attempt to a freeze attack,
            // We will check expiration anyway, but surely this camn be done better
            break;
        }
        
        console.log("Fetched version ", new_version);

        try {
            newroot = await loadRoot(newrootJson, root);
            if (newroot.version <= root.version) {
                throw new Error("New root version is either the same or lesser than the current one. Probable rollback attack.");
            }
            root = newroot;
        } catch (e) {
            console.log(e);
            throw new Error("Datal error loading a new root. Something is *definitely wrong*.");
        }
    }
    if (root.expires > freeze_date) {
        console.log("Succesfully updated root.");
    }
}

async function installListener() {
    updateRoot();
}