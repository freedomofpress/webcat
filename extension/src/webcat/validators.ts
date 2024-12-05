import { parseContentSecurityPolicy } from "./parsers";
import { canonicalize } from "../sigstore/canonicalize";
import { SHA256 } from "./utils";
import { Policy, DataStructure, PopupState, Issuers, OriginState } from "./interfaces";
import { verifyArtifact } from "../sigstore/sigstore";
import { Sigstore } from "../sigstore/interfaces";
import { stringToUint8Array } from "../sigstore/encoding";
import { logger } from "./logger";

export function validateCSP(csp: string) {
  // Here will go the CSP validator of the main_frame
  //const res = parseContentSecurityPolicy(csp);
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
  originState: OriginState,
  tabId: number,
  popupState: PopupState | undefined
) {
  // TODO: Silly hack to match silly development debugging choice:
  const fixedManifest = { manifest: originState.manifest.manifest };
  logger.addLog("debug", canonicalize(fixedManifest), tabId, originState.fqdn);
  var validCount = 0;
  for (const signer of originState.policy.signers) {
    if (originState.manifest.signatures[signer[1]]) {
      try {
        const res = await verifyArtifact(
          sigstore,
          signer[1],
          signer[0],
          originState.manifest.signatures[signer[1]],
          stringToUint8Array(canonicalize(fixedManifest)),
        );
        if (res) {
          logger.addLog("info", `Verified ${signer[0]}, ${signer[1]}`, tabId, originState.fqdn);
          if (popupState) {
            originState.valid_signers.push(signer);
          }
          validCount++;
        }
      } catch (e) {
        console.error(e);
      }
    }
  }

  logger.addLog("info", `threshold: ${originState.policy.threshold}, valid: ${validCount}`, tabId, originState.fqdn);
  if (validCount >= originState.policy.threshold) {
    if (popupState) {
      popupState.valid_signers = originState.valid_signers;
    }
    return true;
  } else {
    return false;
  }
}
