import { loadKeys, checkSignatures } from "./crypto";
import { Metafile } from "./interfaces";

const TUF_REPOSITORY_URL = "https://tuf-repo-cdn.sigstore.dev/";
const STARTING_ROOT_PATH = "assets/1.root.json";

// Listeners
browser.runtime.onInstalled.addListener(installListener);

// Let's keep it simple for now and deal with abstractions later

async function fetchTUFFile(version: string, fileName: string): Promise<any> {
    const url = `${TUF_REPOSITORY_URL}/${version}.${fileName}.json`;
  
    try {
        const response = await fetch(url);
  
        if (!response.ok) {
            throw new Error(`Failed to fetch file: ${response.status} ${response.statusText}`);
        }

        const json = await response.json();
      
        return json;
    } catch (error) {
        console.error("Error fetching TUF file: ", error);
        throw error;
    }
}

async function bootstrapRoot(file: string): Promise<any> {
    console.log("bootstrapRoot");
    try {
        const response = await fetch(browser.runtime.getURL(file));
        const json = await response.json();

        console.log(`${file} read from disk.`);
        return json;
    } catch (error) {
        console.error('Failed to load the JSON file:', error);
    }
}

// This function supports ECDSA (256, 385, 521), Ed25519 in Hex or PEM format
// it is possible to support certain cases of RSA, but it is not really useful for now
// Returns a mapping keyd (hexstring) -> CryptoKey object
async function loadRoot(json: Metafile) {
    console.log("loadRoot")
    
    const _type = json.signed._type;
    if (_type !== "root") {
        throw new Error("Loading the wrong metafile as root.");
    }

    const keys = await loadKeys(json.signed.keys);

    if (await checkSignatures(keys, json.signed, json.signatures) !== true) {
        throw new Error("Failed to verify metafile.");
    }

    console.log("All signatures verified!");
    const expires = json.signed.expires;
}


async function installListener() {
    console.log("installListener");
    const rootJson = await bootstrapRoot(STARTING_ROOT_PATH);
    var root = await loadRoot(rootJson);
}