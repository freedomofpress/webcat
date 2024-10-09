import { updateTUF } from "./sigstore/tuf";
import { loadSigstoreRoot, verifyArtifact } from "./sigstore/sigstore";
import { X509Certificate } from "./sigstore/x509";
import { SigstoreBundle } from "../assets/bundle";

browser.runtime.onInstalled.addListener(installListener);


async function installListener() {
    await updateTUF();
    const root = await loadSigstoreRoot();

    const file = await fetch(browser.runtime.getURL("assets/test_file.txt"));
    const signature = await fetch(browser.runtime.getURL("assets/test_file.txt.sigstore.json"));
    
    const fileraw = new Uint8Array(await file.arrayBuffer());
    const sigjson: SigstoreBundle = await signature.json()

    //console.log(fileraw)
    //console.log(sigjson)

    const cert = X509Certificate.parse(sigjson.verificationMaterial.certificate.rawBytes)

    //for (const ext of cert.extensions.values()) {
    //    console.log(Uint8ArrayToString(ext.value))
    //}

    //console.log("Identity: ", cert.subjectAltName)
    //console.log("Certificate Issuer: ", cert.extFulcioIssuerV2?.issuer)
    //console.log("Verified: ", await cert.verify(root.fulcio))
    //console.log("SCT", cert.extSCT?.signedCertificateTimestamps[0].hashAlgorithm);
    //console.log("SCT", cert.extSCT?.signedCertificateTimestamps[0].logID);
    //console.log("SCT", cert.extSCT?.signedCertificateTimestamps[0].datetime);

    console.log(await verifyArtifact(root, "giulio@freedom.press", "https://accounts.google.com", sigjson, fileraw));
}