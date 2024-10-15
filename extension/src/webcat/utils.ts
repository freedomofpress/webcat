import { TabState } from './interfaces';

export function getFQDN(url: string): string {
    const urlobj = new URL(url);
    return urlobj.hostname;
}

export function isHTTPS(url: string): boolean {
    const urlobj = new URL(url);
    if (urlobj.protocol === "https:") {
        return true;
    } else {
        return false;
    }
}

export function isOnion(url: string): boolean {
    const fqdn = getFQDN(url)
    return (fqdn.substring(fqdn.lastIndexOf('.')) === ".onion");
}


export function isRoot(url: string): boolean {
    const urlobj = new URL(url);
    return (urlobj.pathname === "/")
}


export async function isFQDNEnrolled(fqdn: string): Promise<boolean> {
    const fqdn_hash = await SHA256(fqdn);
    //return fqdn_hash;
    if (fqdn === "nym.re" || fqdn === "lsd.cat") {
        return true;
    } else {
        return false;
    }
}

export function isExtensionRequest(details: browser.webRequest._OnBeforeRequestDetails): boolean {
    return (details.originUrl !== undefined &&
            details.documentUrl !== undefined &&
            details.originUrl.substring(0, 16) === "moz-extension://" &&
            details.documentUrl.substring(0, 16) === "moz-extension://" &&
            details.tabId === -1);
}

export async function SHA256(data: ArrayBuffer|Uint8Array|string) {
    // Sometimes we hash strings, such as the FQDN, sometimes we hash bytes, such as page content
    let inputData: Uint8Array|ArrayBuffer;
    if (typeof(data) === "string") {
        inputData = new TextEncoder().encode(data);
    } else {
        inputData = data;
    }
	var hash = await window.crypto.subtle.digest("SHA-256", inputData)

    return hash;
}

// Ultimately, this silly function decides everything
export function isTabContextOK(tab: TabState): boolean {
    return (tab.validCSP === true &&
            tab.validPolicy === true &&
            tab.validManifest === true)
}

export function arrayBufferToHex(buffer: Uint8Array|ArrayBuffer) {
    var array = Array.from(new Uint8Array(buffer));
    return array.map((b) => b.toString(16).padStart(2, "0")).join("");
}

