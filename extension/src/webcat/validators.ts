import { parseContentSecurityPolicy } from "./parsers";
import { canonicalize } from "../sigstore/canonicalize";
import { SHA256 } from "./utils";
import { Policy, DataStructure } from "./interfaces";
import { bufferEqual } from "../sigstore/crypto";
import { verifyArtifact } from "../sigstore/sigstore";
import { Sigstore } from "../sigstore/interfaces";
import { stringToUint8Array } from "../sigstore/encoding";

export function validateCSP(csp: string) {
  // Here will go the CSP validator of the main_frame
  const res = parseContentSecurityPolicy(csp);
  return true;
}

export async function validate(policy: Policy, csp: string, hash: Uint8Array) {
  // Basic functionality is lookup the policy hash (with a single issuer and identity)
  const canonicalizedPolicy = canonicalize({
    signers: policy.signers,
    threshold: policy.threshold,
  });
  const calculatedHash = new Uint8Array(await SHA256(canonicalizedPolicy));
  //return bufferEqual(calculatedHash, hash);
  return true;
}

export async function validateManifest(
  sigstore: Sigstore,
  manifest: DataStructure,
  policy: Policy,
) {
  // TODO: Silly hack to match silly development debugging choice:
  const fixedManifest = { manifest: manifest.manifest };
  var validCount = 0;
  for (const signer of policy.signers) {
    if (manifest.signatures[signer[1]]) {
      try {
        const res = await verifyArtifact(
          sigstore,
          signer[1],
          signer[0],
          manifest.signatures[signer[1]],
          stringToUint8Array(canonicalize(fixedManifest)),
        );
        if (res) {
          console.log("Verified", signer[0], signer[1]);
          validCount++;
        }
      } catch (e) {
        console.error(e);
      }
    }
  }

  console.log(`threshold: ${policy.threshold}, valid: ${validCount}`);
  if (validCount >= policy.threshold) {
    return true;
  } else {
    return false;
  }
}
