import { loadKeys, checkSignatures, getRoleKeys } from "./crypto";
import { Uint8ArrayToString, Uint8ArrayToHex } from "./encoding";
import { Metafile, Root, Roles, Meta, HashAlgorithms } from "./interfaces";

const TUF_REPOSITORY_URL = "https://tuf-repo-cdn.sigstore.dev";
const STARTING_ROOT_PATH = "assets/1.root.json";

// Listeners
browser.runtime.onInstalled.addListener(installListener);

// Let's keep it simple for now and deal with abstractions later

async function fetchMetafile(role: string, version?: number|string, json: boolean = true): Promise<any> {
    var url: string = "";
    if (version) {
        url = `${TUF_REPOSITORY_URL}/${version}.${role}.json`;
    } else {
        url = `${TUF_REPOSITORY_URL}/${role}.json`;
    }
  
    console.log("Fetching ", url)
    try {
        const response = await fetch(url);
  
        if (!response.ok) {
            throw new Error(`Failed to fetch file: ${response.status} ${response.statusText}`);
        }

        if (json) {
            return await response.json();
        } else {
            return await response.arrayBuffer();
        }
      
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

    if (json.signed._type !== Roles.Root) {
        throw new Error("Loading the wrong metafile as root.");
    }

    var keys: Map<string, CryptoKey>;
    var threshold: number;

    // If no oldroot, this is a fresh start froma trusted file, so it's self signed
    if (oldroot == undefined) {
        keys = await loadKeys(json.signed.keys);
        // ~~We want to check everybody signed the bootstrap file or I wish~~
        // Instead we are using the threshold specified in the same file
        threshold = json.signed.roles.root.threshold;
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
        threshold: json.signed.roles.root.threshold,
        consistent_snapshot: json.signed.consistent_snapshot,
        roles: json.signed.roles
    };
}

async function updateRoot(frozenTimestamp: Date): Promise<Root> {
    const cached = await browser.storage.local.get([Roles.Root]);
    var rootJson = cached.root;

    // Is this the first time we are running the update meaning we have no cached file?
    if (rootJson == undefined) {
        // Then load the hardcoded startup root
        console.log("Starting from hardcoded root");
        // Spec 5.2
        rootJson = await openBootstrapRoot(STARTING_ROOT_PATH);
    }

    var root = await loadRoot(rootJson as Metafile);
    let newroot;

    // In theory max version is the maximum integer size, probably 2^32 per the spec, in practice this should be safe for a century
    for (var new_version = root.version + 1; new_version < 8192; new_version++) {

        try {
            var newrootJson = await fetchMetafile(Roles.Root, new_version);
        } catch {
            // Fetching failed and we assume there is no new version
            // Maybe we should explicitly check for 404 failures
            // Cause a network failure may be an attempt to a freeze attack,
            // We will check expiration anyway, but surely this camn be done better
            break;
        }
        
        //console.log("Fetched version ", new_version);

        try {
            // First check that is properly signed by the previous root
            newroot = await loadRoot(newrootJson, root);
            // As per 5.3.5 of the SPEC
            if (newroot.version <= root.version) {
                throw new Error("New root version is either the same or lesser than the current one. Probable rollback attack.");
            }
            // Then check it is properly signed by itself as per 5.3.4 of the SPEC
            newroot = await loadRoot(newrootJson);
            root = newroot;
        } catch (e) {
            console.log(e);
            throw new Error("Error loading a new root. Something is *definitely wrong*.");
        }
        // By spec 5.3.8, we should update the cache now
        browser.storage.local.set({[Roles.Root]: newrootJson });

    }

    // We do not cast expires because it is done in loadRoot
    if (root.expires <= frozenTimestamp) {
        // By spec 5.3.10
        throw new Error("Freeze attack on the root metafile.");
    }

    // TODO SECURITY ALERT: We are skipping 5.3.11, let's just load the keys for now
    return root;
}

async function updateTimestamp(root: Root, frozenTimestamp: Date): Promise<number> {
    // Funny question about 5.5.2, why are not hashes in the timestamp?
    // https://github.com/sigstore/root-signing/issues/1388

    // Always remember to select only the keys delegated to a specific role
    const keys = getRoleKeys(root.keys, root.roles.timestamp.keyids);

    const cached = await browser.storage.local.get([Roles.Timestamp]);
    const cachedTimestamp = cached.timestamp;

    // Spec 5.4.1
    const newTimestamp = await fetchMetafile(Roles.Timestamp);

    try {
        // Spec 5.4.2
        await checkSignatures(keys, newTimestamp.signed, newTimestamp.signatures, root.roles.timestamp.threshold);
    } catch { 
        throw new Error("Failed verifying timestamp role signature(s).");
    }

    // Spec 5.4.3.x apply only if we already have a cached file supposedly
    if (cachedTimestamp !== undefined) {
        // 5.4.3.1 if lower, this is a rollback attack
        if (newTimestamp.signed.version < cachedTimestamp.signed.version) {
            throw new Error("New timestamp file has a lower version that the currently cached one.");
        }
        if (newTimestamp.signed.version == cachedTimestamp.signed.version) {
            // If equal, there is no update and we can just skip here
            // Return false, there are no updates
            return -1;
        }
        // 5.4.3.2
        if (newTimestamp.signed.meta["snapshot.json"].version < cachedTimestamp.signed.meta["snapshot.json"].version) {
            throw new Error("Timestamp has been updated, but snapshot version has been rolled back.");
        }
    }

    if (new Date(newTimestamp.signed.expires) <= frozenTimestamp) {
        throw new Error("Freeze attack on the timestamp metafile.");
    }

    browser.storage.local.set({[Roles.Timestamp]: newTimestamp})
    return newTimestamp.signed.meta["snapshot.json"].version;
}

async function updateSnapshot(root: Root, frozenTimestamp: Date, version?: number): Promise<Meta> {

    const keys = getRoleKeys(root.keys, root.roles.snapshot.keyids);

    const cached = await browser.storage.local.get([Roles.Snapshot]);
    const cachedSnapshot = cached.snapshot;

    let newSnapshot;

    // Spec 5.5.1
    if (root.consistent_snapshot) {
        newSnapshot = await fetchMetafile(Roles.Snapshot, version);
    } else {
        newSnapshot = await fetchMetafile(Roles.Snapshot);
    }

    // As mentioned we are skipping 5.5.2 because sigstore timestamp does not have hashes
    // Even if they add it, we would be doing a check less, but we won't break
    // TODO revisit

    try {
        // Spec 5.5.3
        await checkSignatures(keys, newSnapshot.signed, newSnapshot.signatures, root.roles.snapshot.threshold);
    } catch { 
        throw new Error("Failed verifying snapshot role signature(s).");
    }

    // 5.5.4
    if (newSnapshot.signed.version !== version) {
        throw new Error("Snapshot file version does not match timestamp version.");
    }

    // 5.5.5
    if (cachedSnapshot !== undefined) {
        for (const [target] of Object.entries(cachedSnapshot.signed.meta)) {
            if (!newSnapshot.signed.meta.has(target)) {
                throw new Error("Target that was listed in an older snapshot was dropped in a newer one.");
            }
            if (newSnapshot.signed.meta[target].version < cachedSnapshot.signed.meta[target].version) {
                throw new Error("Target version in newer snapshot is lower than the cached one. Probable rollback attack.");
            }
        }
    }

    // 5.5.6
    if (new Date(newSnapshot.signed.expires) <= frozenTimestamp) {
        throw new Error("Freeze attack on the snapshot metafile.");
    }

    // 5.5.7
    browser.storage.local.set({[Roles.Snapshot]: newSnapshot})

    // If we reach here, we expect updates, otherwise we would have aborted in the timestamp phase.
    return newSnapshot.signed.meta;
}

async function updateTargets(root: Root, frozenTimestamp: Date, snapshot: Meta) {
    const keys = getRoleKeys(root.keys, root.roles.targets.keyids);

    console.log(root.keys)
    console.log(keys)

    const cached = await browser.storage.local.get([Roles.Targets]);
    const cachedTargets = cached.targets;
    
    let newTargets;

    // Spec 5.6.1
    if (root.consistent_snapshot) {
        newTargets = await fetchMetafile(Roles.Targets, snapshot[`${Roles.Targets}.json`].version);
    } else {
        newTargets = await fetchMetafile(Roles.Targets);
    }

    // TODO SECURITY: Let's skip 5.6.2 for now, feels like the hashes do not provide a lot
    // We are skipping for laziness, we'd need to download the raw file and not the json, and build the digest

    try {
        // Spec 5.6.3
        await checkSignatures(keys, newTargets.signed, newTargets.signatures, root.roles.targets.threshold);
    } catch (e) { 
        console.log(e)
        throw new Error("Failed verifying targets role signature(s).");
    }

    // 5.6.4
    if (cachedTargets !== undefined && newTargets.signed.version < cachedTargets.signed.version) {
        throw new Error("Targets version is lower than the cached one. Probable rollback attack.");
    }

    // 5.6.5
    if (new Date(newTargets.signed.expires) <= frozenTimestamp) {
        throw new Error("Freeze attack on the targets metafile.");
    }

    // 5.6.6
    browser.storage.local.set({[Roles.Targets]: newTargets})
}

async function fetchSigstoreTrustRoot() {
    const cached = await browser.storage.local.get([Roles.Targets])
    const cachedTargets = cached[Roles.Targets]

    if (cachedTargets === undefined) {
        throw new Error("Failed to find the targets metafile when it should have existed.");
    }
    // Both sha256 and sha512 works for downloading the file (and verifying of course)
    const sha256 = cachedTargets.signed.targets["trusted_root.json"].hashes.sha256;


    const trusted_root_raw = await fetchMetafile("trusted_root", `targets/${sha256}`, false);
    const sha256_calculated = Uint8ArrayToHex(new Uint8Array(await crypto.subtle.digest(HashAlgorithms.SHA256, trusted_root_raw)));

    // We can't directly compare uint8array because it's an object, there would be a faster trick
    // But it's still not great IndexedDB.cmp(a, b)

    if (sha256 !== sha256_calculated) {
        throw new Error("trusted_root.json hash does not match TUF value.");
    }

    console.log(JSON.parse(Uint8ArrayToString(trusted_root_raw)));
    console.log("Success!")
}

async function updateTUF() {
    // Spec 5.1
    const frozenTimestamp = new Date();
    const root: Root = await updateRoot(frozenTimestamp);
    const snapshotVersion: number = await updateTimestamp(root, frozenTimestamp);

    // As per spec 5.4.3.1 we shall abort the whole updating if a new snapshot is not available
    if (snapshotVersion < 0) {
        return;
    }
    const snapshot = await updateSnapshot(root, frozenTimestamp, snapshotVersion);
    await updateTargets(root, frozenTimestamp, snapshot);
}

async function installListener() {
    await updateTUF();
    await fetchSigstoreTrustRoot();
}