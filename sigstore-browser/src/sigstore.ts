import { Roles, RawLogs, RawCAs, SigstoreRoots, Sigstore } from "./interfaces"
import { importKey } from "./crypto"

async function loadLog(frozenTimestamp: Date, logs: RawLogs): Promise<CryptoKey> {
    // We will stop at the first valid one
    // We do not support more than one valid one at a time, not sure if Sigstore does...

    for (const log of logs) {
        // if start date is not in the future, and if an end doesnt exist or is in the future
        if (frozenTimestamp > new Date(log.publicKey.validFor.start) && (!log.publicKey.validFor.end || new Date(log.publicKey.validFor.end) > frozenTimestamp)) {
            return await importKey(log.publicKey.keyDetails, log.publicKey.keyDetails, log.publicKey.rawBytes);
        }
    }

    throw new Error("Could not find a valid key in sigstore root.");
}

async function loadCA(frozenTimestamp: Date, cas: RawCAs) {

    for (const ca of cas) {
        // if start date is not in the future, and if an end doesnt exist or is in the future
        if (frozenTimestamp > new Date(ca.validFor.start) && (!ca.validFor.end || new Date(ca.validFor.end) > frozenTimestamp)) {
            //return await importKey(log.publicKey.keyDetails, log.publicKey.keyDetails, log.publicKey.rawBytes);
            console.log(ca.certChain);
            return
        }
    }
    throw new Error("Could not find a valid CA in sigstore root.");
}


export async function loadSigstoreRoot(): Promise<undefined> {
    const cached = await browser.storage.local.get([Roles.TrustedRoot])
    const root = cached[Roles.TrustedRoot];

    
    // Let's learn from TUF and load all pieces relative from a single point in time
    const frozenTimestamp = new Date();

    try {
    await loadLog(frozenTimestamp, root[SigstoreRoots.tlogs])
    await loadLog(frozenTimestamp, root[SigstoreRoots.ctlogs]),
    await loadCA(frozenTimestamp, root[SigstoreRoots.certificateAuthorities])
    await loadCA(frozenTimestamp, root[SigstoreRoots.timestampAuthorities])
    } catch (e) {
        console.log(e)
    }

    /*return {
        rekor: await loadLog(frozenTimestamp, root[SigstoreRoots.tlogs]),
        fulcio: CryptoKey,
        ctfe: await loadLog(frozenTimestamp, root[SigstoreRoots.ctlogs]),
        tsa: CryptoKey
    }*/

}