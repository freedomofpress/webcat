import { OriginState, PopupState, metadataRequestSource } from "./interfaces";
import { isFQDNEnrolled } from "./db";
import { logger } from "./logger";
import { setIcon } from "./ui";
import { origins } from "./listeners";

export async function validateOrigin(
  tabs: Map<number, string>,
  popups: Map<number, PopupState>,
  fqdn: string,
  url: string,
  tabId: number,
  type: metadataRequestSource,
) {
  const policyHash = await isFQDNEnrolled(fqdn, tabId);
  if (policyHash === false) {
    console.debug(`${url} is not enrolled, skipping...`);
    return;
  }

  if (type === metadataRequestSource.main_frame) {
    const newPopupState = new PopupState(fqdn, tabId);
    popups.set(tabId, newPopupState);
    setIcon(tabId);
  }

  // See https://github.com/freedomofpress/webcat/issues/1
  const urlobj = new URL(url);
  if (
    !["80", "443", ""].includes(urlobj.port) || // Ports 80, 443, or no port specified.
    !["http:", "https:"].includes(urlobj.protocol) // Protocol must be HTTP or HTTPS.
  ) {
    throw new Error(
      `Attempting to load an enrolled resource using protocol "${urlobj.protocol}" and port "${urlobj.port || "(default)"}". Only standard protocols (HTTP/HTTPS) and ports (80/443) are allowed.`,
    );
  }

  // If the website is enrolled but is not https force a redirect
  // Or maybe not if it's an onion website :)
  if (
    urlobj.protocol !== "https:" &&
    urlobj.hostname.substring(fqdn.lastIndexOf(".")) !== ".onion"
  ) {
    urlobj.protocol = "https:";
    // Redirect to HTTPS
    return { redirectUrl: urlobj.toString() };
  }

  // We support one enrollment/policy per domain, to enforce SOP isolation
  //if (urlobj.pathname !== "/") {
  //  throw new Error("Enrolled applications should be loaded from the root.");
  //}

  // Nothing can go wrong in this func anynmore hopefully, let's add the reference
  if (type === metadataRequestSource.main_frame) {
    tabs.set(tabId, fqdn);
  }

  // If origin metadata are already loaded, just skip doing it again and return early
  if (origins.has(fqdn)) {
    // Since we use cached info, we should still populate the popup with the cached info
    const popupState = popups.get(tabId);
    if (popupState) {
      // TODO
      //popupState.valid_headers =
      // We want it undefined, because we have not verified it yet
      popupState.valid_manifest = origins.get(fqdn)?.valid
        ? origins.get(fqdn)!.valid
        : undefined;
      popupState.threshold = origins.get(fqdn)!.policy.threshold;
      popupState.valid_signers = origins.get(fqdn)!.valid_signers;
    }
    return;
  }

  // Generate a new state for the origin
  logger.addLog(
    "info",
    `${fqdn} is enrolled, but we do not have metadata yet.`,
    tabId,
    fqdn,
  );
  const newOriginState = new OriginState(fqdn);
  console.log(`Adding ${fqdn} to origins`);
  origins.set(fqdn, newOriginState);

  // So, we cannot directly know that we are the initiator of this request, see
  // https://stackoverflow.com/questions/31129648/how-to-identify-who-initiated-the-http-request-in-firefox
  // It's tracked in the dev console, but no luck in extensions https://discourse.mozilla.org/t/access-webrequest-request-initiator-chain-stack-trace/75877
  // More sadness: https://stackoverflow.com/questions/47331875/webrequest-api-how-to-get-the-requestid-of-a-new-request

  if (policyHash instanceof Uint8Array && policyHash.byteLength == 32) {
    newOriginState.policyHash = policyHash;
  } else {
    throw new Error("Error retrieving the policy hash.");
  }
}
