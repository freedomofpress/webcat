import { TabState } from './interfaces';
import { getFQDN, isFQDNEnrolled, isHTTPS, isOnion } from './utils';

export async function validateMainFrame(tabs: Map<number, TabState>, details: browser.webRequest._OnBeforeRequestDetails) {
    console.log(`New main_frame and so new tab context for ${details.url}`);
    var newTabState: TabState = new TabState();
    tabs.set(details.tabId, newTabState);

    newTabState.fqdn = getFQDN(details.url);
    newTabState.isEnrolled = await isFQDNEnrolled(newTabState.fqdn);
    console.log(`FQDN is ${newTabState.fqdn}, enrolled: ${newTabState.isEnrolled}`);

    // If the website is enrolled but is loading via HTTP abort anyway
    // Or maybe not if it's an onion website :)
    if (newTabState.isEnrolled === true && isHTTPS(details.url) === false && isOnion(details.url) === false) {
        throw new Error("Attempting to load HTTP resource for a non-onion enrolled FQDN!")
    }

    // Do we care about this? What matters in the end is the main_frame context
    //if (newTabState.isEnrolled === true && isRoot(details.url) === false) {
    //    newTabState.errors.push("Attempting to load the application from a non-root path! EXIT!");
    //}

    // Fire manifest request in the background, but do not wait for it now
    if (newTabState.isEnrolled === true) {
        // So, we cannot directly know that we are the initiator of this request, see
        // https://stackoverflow.com/questions/31129648/how-to-identify-who-initiated-the-http-request-in-firefox
        // It's tracked in the dev console, but no luck in extensions https://discourse.mozilla.org/t/access-webrequest-request-initiator-chain-stack-trace/75877
        // still we do not want to intercept this one :)
        // More sadness: https://stackoverflow.com/questions/47331875/webrequest-api-how-to-get-the-requestid-of-a-new-request
        console.log(`Fetching manifest at https://${newTabState.fqdn}/manifest.json`);
        newTabState.manifestPromise = fetch(`https://${newTabState.fqdn}/manifest.json`);
    }
}