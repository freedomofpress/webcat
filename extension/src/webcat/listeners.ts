import { updateTUF } from "../sigstore/tuf";
import { loadSigstoreRoot } from "../sigstore/sigstore"
import { Sigstore } from "../sigstore/interfaces";
import { TabState } from "./interfaces";
import { validateResponseHeaders, validateResponseContent } from './response';
import { validateMainFrame } from './request';
import { isExtensionRequest } from "./utils";

const tabs: Map<number, TabState> = new Map();
let sigstore: Sigstore;
const allowed_types: string[] = ["image", "font", "media", "object", "xmlhttprequest", "websocket"];

export async function installListener() {
    // Initial list download here
    // We probably want do download the most recent list, verify signature and log inclusion
    // Then index persistently in indexeddb. We do this at every startup anyway, so there is no reason for
    // not just calling the startup listener
    await startupListener();
};

export async function startupListener() {
    await updateTUF();
    sigstore = await loadSigstoreRoot();
    // Here we probably want to check for a diff update to the list
    // Stills needs to check signature and inclusion proof
    // But db update should be on average very very small
};

export function tabCloseListener(tabId: number, removeInfo?: browser.tabs._OnRemovedRemoveInfo) {
    tabs.delete(tabId);
}

export async function headersListener(details: browser.webRequest._OnHeadersReceivedDetails): Promise<browser.webRequest.BlockingResponse> {

    // Skip allowed types
    if (isExtensionRequest(details) || 
        allowed_types.includes(details.type)
    ) {
        console.log(`headersListener: skipping ${details.url}`);
        return {};
    }

    // We checked for enrollment back when the request was fired
    var tabState = tabs.get(details.tabId);

    if (!tabState) {
        console.log(`Processing response headers for ${details.url}, but a tab state does not exists.`);
        return {"cancel": true};
    }

    if (tabState.isEnrolled === true && details.type == "main_frame") {
        try {
            await validateResponseHeaders(tabState, details);
        } catch (error) {
            console.log("Error when parsing response headers:", error);
            return {"cancel": true};
        }
    }
    return {};
};

export async function requestListener(details: browser.webRequest._OnBeforeRequestDetails): Promise<browser.webRequest.BlockingResponse> {

    //console.log(details.url);
    //console.log(details.type);
    //console.log(details);
    if (isExtensionRequest(details) || 
        allowed_types.includes(details.type)
    ) {
        // We will always wonder, is this check reasonable?
        // Might be redundant anyway if we skip xmlhttprequest
        // But we probably want to also ensure other extensions work
        console.log(`requestListener: skipping ${details.url}`);
        return {};
    }

    if (details.type == "main_frame") {
        try {
            await validateMainFrame(tabs, details);
        } catch (error) {
            console.log("Error loading main_frame: ", error);
            return {"cancel": true};
        }
    }

    // All this should happen only if the website is ultimately enrolled
    // Below here TabState should not change, hence for safety just load it as a const.
    // This should never happen, but still let's guard for it
    const tabState = tabs.get(details.tabId);
    if (!tabState) {
        console.log(`Something went incredibly wrong for ${details.url}`);
        console.log(details);
        //return {"cancel": true};
    }

    if (tabState!.isEnrolled === true) {
        validateResponseContent(tabState!, details);
    }

    // See https://developer.mozilla.org/en-US/docs/Mozilla/Add-ons/WebExtensions/API/webRequest/BlockingResponse
    // Returning a response here is a very powerful tool, let's think about it later
    return {};
}
