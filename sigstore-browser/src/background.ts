import { updateTUF } from "./tuf";
import { loadSigstoreRoot } from "./sigstore";

browser.runtime.onInstalled.addListener(installListener);


async function installListener() {
    await updateTUF();
    const root = await loadSigstoreRoot();
    console.log(root);
    console.log(await root.fulcio.publicKeyObj)

}