import { Roles, RawLogs, RawCAs, SigstoreRoots, Sigstore } from "./interfaces"
import { importKey } from "./crypto"
import { X509Certificate, X509SCTExtension, EXTENSION_OID_SCT } from "./x509";
import { SigstoreBundle } from "../../assets/bundle";
import { ByteStream } from "./stream";

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

// Adapted from https://github.com/sigstore/sigstore-js/blob/main/packages/verify/src/key/sct.ts
export async function verifySCT(cert: X509Certificate, issuer: X509Certificate, ctlog: CryptoKey): Promise<boolean> {
    let extSCT: X509SCTExtension | undefined;
  
    // Verifying the SCT requires that we remove the SCT extension and
    // re-encode the TBS structure to DER -- this value is part of the data
    // over which the signature is calculated. Since this is a destructive action
    // we create a copy of the certificate so we can remove the SCT extension
    // without affecting the original certificate.
    const clone = cert.clone();
  
    // Intentionally not using the findExtension method here because we want to
    // remove the the SCT extension from the certificate before calculating the
    // PreCert structure
    for (let i = 0; i < clone.extensions.length; i++) {
      const ext = clone.extensions[i];
  
      if (ext.subs[0].toOID() === EXTENSION_OID_SCT) {
        extSCT = new X509SCTExtension(ext);
  
        // Remove the extension from the certificate
        clone.extensions.splice(i, 1);
        break;
      }
    }
  
    // No SCT extension found to verify
    if (!extSCT) {
      throw new Error("No SCT exension was found.");
    }
  
    // Found an SCT extension but it has no SCTs
    if (extSCT.signedCertificateTimestamps.length === 0) {
        throw new Error("No SCT was found in the SCT extension.");
    }

  
    // Construct the PreCert structure
    // https://www.rfc-editor.org/rfc/rfc6962#section-3.2
    const preCert = new ByteStream();
  
    // Calculate hash of the issuer's public key
    const issuerId = new Uint8Array(await crypto.subtle.digest("SHA-256", issuer.publicKey));
    preCert.appendView(issuerId);
  
    // Re-encodes the certificate to DER after removing the SCT extension
    const tbs = clone.tbsCertificate.toDER();
    preCert.appendUint24(tbs.length);
    preCert.appendView(tbs);
  
    // Let's iterate over the SCTs, if there are more than one, and see if we can validate at least one
    for (const logId of extSCT.signedCertificateTimestamps.keys()) {
        const sct = extSCT.signedCertificateTimestamps[logId];

        if (sct.datetime < cert.notBefore || sct.datetime > cert.notAfter) {
            throw new Error("SCT timestamp does not fall within certificate validity.");
        }

        if (await sct.verify(preCert.buffer, ctlog)) {
            return true;
        }
    }
    
    throw new Error("SCT verification failed.");
  }

export async function verifyArtifact(root: Sigstore, identity: string, issuer: string, bundle: SigstoreBundle, data: Uint8Array): Promise<boolean> {
    // Quick checks first: does the signing certificate have the correct identity?
    const signingCert = X509Certificate.parse(bundle.verificationMaterial.certificate.rawBytes);

    // Basic stuff
    if (signingCert.subjectAltName !== identity) {
        throw new Error("Certificate identity (subjectAltName) do not match the verifying one.");
    }

    if (signingCert.extFulcioIssuerV2?.issuer !== issuer) {
        throw new Error("Identity issuer is not the verifying one.");
    }

    if (!signingCert.verify(root.fulcio)) {
        throw new Error("Signing certificate has not been signed by the current Fulcio CA.");
    }
    
    // This check is not complete, we should check every ca in the chain. This is silly we know they are long lived
    // and we need performance
    if (signingCert.notBefore < root.fulcio.notBefore || signingCert.notBefore > root.fulcio.notAfter) {
        throw new Error("Signing cert was signed when the Fulcio CA was not valid.");
    }

    // To verify the SCT we need to build a preCert (because the cert was logged without the SCT)
    // https://github.com/sigstore/sigstore-js/packages/verify/src/key/sct.ts#L45

    if (!await verifySCT(signingCert, root.fulcio, root.ctfe)) {
        throw new Error("SCT validation failed.");
    }

    return true;
}