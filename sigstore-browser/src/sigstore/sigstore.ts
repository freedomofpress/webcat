import { Roles, RawLogs, RawCAs, SigstoreRoots, Sigstore } from "./interfaces"
import { importKey } from "./crypto"
import { X509Certificate } from "./x509";

async function loadLog(frozenTimestamp: Date, logs: RawLogs): Promise<CryptoKey> {
    // We will stop at the first valid one
    // We do not support more than one valid one at a time, not sure if Sigstore does
    // But it probably do to verify past artifacts: otherwise things still valid today might be discarded

    for (const log of logs) {
        // if start date is not in the future, and if an end doesnt exist or is in the future
        if (frozenTimestamp > new Date(log.publicKey.validFor.start) && (!log.publicKey.validFor.end || new Date(log.publicKey.validFor.end) > frozenTimestamp)) {
            return await importKey(log.publicKey.keyDetails, log.publicKey.keyDetails, log.publicKey.rawBytes);
        }
    }

    throw new Error("Could not find a valid key in sigstore root.");
}

async function loadCA(frozenTimestamp: Date, cas: RawCAs): Promise<X509Certificate> {

    for (const ca of cas) {
        // if start date is not in the future, and if an end doesnt exist or is in the future
        if (frozenTimestamp > new Date(ca.validFor.start) && (!ca.validFor.end || new Date(ca.validFor.end) > frozenTimestamp)) {

            let parentCert: X509Certificate;
            let currentCert: X509Certificate;
            for (const cert of ca.certChain.certificates.reverse()) {
                currentCert = X509Certificate.parse(cert.rawBytes)

                if (parentCert! == undefined) {
                    parentCert = currentCert;

                    // So we are expecting a root here, so it has to be self sigend
                    if (!await currentCert.verify()) {
                        throw new Error("Root cert self signature does not verify.");
                    }
                } else {
                    if (!await currentCert.verify(parentCert)) {
                        throw new Error("Error verifying the certificate chain.");
                    }
                }
                if (!currentCert.validForDate(frozenTimestamp)) {
                    throw new Error("A certificate in the chain is not valid at the current date.");
                }
            }
            return currentCert!;
        }
    }
    throw new Error("Could not find a valid CA in sigstore root.");
}

export async function loadSigstoreRoot(): Promise<Sigstore> {
    const cached = await browser.storage.local.get([Roles.TrustedRoot])
    const root = cached[Roles.TrustedRoot];

    
    // Let's learn from TUF and load all pieces relative from a single point in time
    const frozenTimestamp = new Date();

    return {
        rekor: await loadLog(frozenTimestamp, root[SigstoreRoots.tlogs]),
        ctfe: await loadLog(frozenTimestamp, root[SigstoreRoots.ctlogs]),
        fulcio: await loadCA(frozenTimestamp, root[SigstoreRoots.certificateAuthorities])
        // Sigstore community is not using timestampAuthorities for now
    }
}