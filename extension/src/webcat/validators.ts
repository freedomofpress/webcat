import { canonicalize } from "../sigstore/canonicalize";
import { SHA256 } from "./utils";
import {
  Policy,
  PopupState,
  OriginState,
} from "./interfaces";
import { verifyArtifact } from "../sigstore/sigstore";
import { Sigstore } from "../sigstore/interfaces";
import { stringToUint8Array } from "../sigstore/encoding";
import { logger } from "./logger";
import { parseContentSecurityPolicy } from './parsers';
import { isFQDNEnrolled } from "./db";
import { getFQDN } from "./utils";

import { origins, list_db } from "./listeners";

// This functions shouldnt take this many arguments; TODO refactor or import/export global objects
export async function validateCSP(csp: string, fqdn: string, tabId: number): Promise<boolean> {
  // See https://github.com/freedomofpress/webcat/issues/9
  // https://github.com/freedomofpress/webcat/issues/3
  const required_directives = ["script-src", "style-src", "object-src"];

  const parsedCSP = parseContentSecurityPolicy(csp);
  logger.addLog("info", `Parsed CSP: ${parsedCSP.values()}`, tabId, fqdn);

  const requiredDirectives = ["script-src", "style-src", "object-src"];
  const allowedScriptSrc = new Set(["'self'", "'wasm-unsafe-eval'"]);
  const allowedStyleSrc = new Set(["'self'", "'unsafe-inline'"]);

  // Ensure required directives exist
  for (const directive of requiredDirectives) {
    if (!parsedCSP.has(directive)) {
      throw new Error(`Missing required directive: ${directive}`);
    }
  }

  // Validate script-src
  const scriptSrc = parsedCSP.get("script-src")!;
  for (const src of scriptSrc) {
    if (!allowedScriptSrc.has(src) && !src.startsWith("'sha") && !await isFQDNEnrolled(list_db, getFQDN(src), origins, tabId)) {
      throw new Error(`Invalid source in script-src: ${src}`);
    }
  }

  // Validate style-src
  const styleSrc = parsedCSP.get("style-src")!;
  for (const src of styleSrc) {
    if (!allowedStyleSrc.has(src)) {
      throw new Error(`Invalid source in style-src: ${src}`);
    }
  }

  // Validate object-src
  const objectSrc = parsedCSP.get("object-src")!;
  if (objectSrc.length !== 1 || objectSrc[0] !== "'none'") {
    throw new Error(`object-src must be 'none', found: ${objectSrc.join(" ")}`);
  }

  // Validate child-src and frame-src individually
  const childSrc = parsedCSP.get("child-src") ?? [];
  const frameSrc = parsedCSP.get("frame-src") ?? [];
  const workerSrc = parsedCSP.get("worker-src") ?? [];

  // TODO, you can probably never have an external worker src without an external script-src
  for (const src of [...childSrc, ...frameSrc, ...workerSrc]) {
    if (src.includes("*")) {
      throw new Error(`Wildcards not allowed child-src/frame-src: ${src}`);
    }
    if (src != "'none'" && src != "'self'" && !await isFQDNEnrolled(list_db, getFQDN(src), origins, tabId)) {
      throw new Error(`Invalid source in child-src/frame-src: ${src}`);
    }
  }
  
  logger.addLog("info", "CSP validation successful!", tabId, fqdn);
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
  popupState: PopupState | undefined,
) {
  // TODO: Silly hack to match silly development debugging choice:
  if (!originState.manifest) {
    return false;
  }
  const fixedManifest = { manifest: originState.manifest.manifest };
  logger.addLog("debug", canonicalize(fixedManifest), tabId, originState.fqdn);
  let validCount = 0;
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
          logger.addLog(
            "info",
            `Verified ${signer[0]}, ${signer[1]}`,
            tabId,
            originState.fqdn,
          );
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

  logger.addLog(
    "info",
    `threshold: ${originState.policy.threshold}, valid: ${validCount}`,
    tabId,
    originState.fqdn,
  );
  if (validCount >= originState.policy.threshold) {
    if (popupState) {
      popupState.valid_signers = originState.valid_signers;
    }
    return true;
  } else {
    return false;
  }
}