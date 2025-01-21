import { canonicalize } from "../sigstore/canonicalize";
import { stringToUint8Array } from "../sigstore/encoding";
import { SigstoreVerifier } from "../sigstore/sigstore";
import { isFQDNEnrolled } from "./db";
import { OriginState, PopupState } from "./interfaces";
import { logger } from "./logger";
import { parseContentSecurityPolicy } from "./parsers";
import { getFQDNSafe } from "./utils";

export async function validateCSP(
  csp: string,
  fqdn: string,
  tabId: number,
): Promise<boolean> {
  // See https://github.com/freedomofpress/webcat/issues/9
  // https://github.com/freedomofpress/webcat/issues/3

  const parsedCSP = parseContentSecurityPolicy(csp);
  logger.addLog("info", `Parsed CSP: ${parsedCSP.values()}`, tabId, fqdn);

  const requiredDirectives = ["script-src", "style-src", "object-src"];
  const allowedScriptSrc = new Set(["'self'", "'wasm-unsafe-eval'"]);
  const allowedStyleSrc = new Set([
    "'self'",
    "'unsafe-inline'",
    "'unsafe-hashes'",
  ]);

  // Ensure required directives exist
  for (const directive of requiredDirectives) {
    if (!parsedCSP.has(directive)) {
      throw new Error(`Missing required directive: ${directive}`);
    }
  }

  // Validate script-src
  // We can ignore, the check of existance is done in the loop above
  // eslint-disable-next-line @typescript-eslint/no-non-null-assertion
  const scriptSrc = parsedCSP.get("script-src")!;
  for (const src of scriptSrc) {
    if (
      !allowedScriptSrc.has(src) &&
      !src.startsWith("'sha") /*&&
      TODO: we will eventually decide if we want to source scripts/styles from third parties, i'd say no
      !(await isFQDNEnrolled(getFQDNSafe(src), tabId))*/
    ) {
      throw new Error(`Invalid source in script-src: ${src}`);
    }
  }

  // Validate style-src
  // eslint-disable-next-line @typescript-eslint/no-non-null-assertion
  const styleSrc = parsedCSP.get("style-src")!;
  for (const src of styleSrc) {
    if (!allowedStyleSrc.has(src)) {
      throw new Error(`Invalid source in style-src: ${src}`);
    }
  }

  // Validate object-src
  // eslint-disable-next-line @typescript-eslint/no-non-null-assertion
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
    if (
      src != "'none'" &&
      src != "'self'" &&
      !(await isFQDNEnrolled(getFQDNSafe(src), tabId))
    ) {
      throw new Error(`Invalid source in child-src/frame-src: ${src}`);
    }
  }

  logger.addLog("info", "CSP validation successful!", tabId, fqdn);
  return true;
}

export async function validateManifest(
  sigstore: SigstoreVerifier,
  originState: OriginState,
  tabId: number,
  popupState: PopupState | undefined,
) {
  if (
    !originState.manifest ||
    !originState.manifest.signatures ||
    !originState.manifest.manifest ||
    Object.keys(originState.manifest.signatures).length <
      originState.policy.threshold
  ) {
    return false;
  }

  const fixedManifest = { manifest: originState.manifest.manifest };
  logger.addLog("debug", canonicalize(fixedManifest), tabId, originState.fqdn);
  let validCount = 0;
  for (const signer of originState.policy.signers) {
    if (originState.manifest.signatures[signer[1]]) {
      try {
        const res = await sigstore.verifyArtifact(
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
