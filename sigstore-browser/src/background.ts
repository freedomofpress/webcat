import { updateTUF } from "./tuf";
import { loadSigstoreRoot } from "./sigstore";

browser.runtime.onInstalled.addListener(installListener);


async function installListener() {
    await updateTUF();
    await loadSigstoreRoot();

}