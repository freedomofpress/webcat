import { version } from "./../config";
import { origins, popups, tabs } from "./../globals";
import { getFQDNPolicy, list_count } from "./db";
import { metadataRequestSource } from "./interfaces/base";
import {
  OriginStateHolder,
  OriginStateInitial,
} from "./interfaces/originstate";
import { PopupState } from "./interfaces/popupstate";
import { sigstore } from "./listeners";
import { logger } from "./logger";
import { setIcon } from "./ui";

export async function validateOrigin(
  fqdn: string,
  url: string,
  tabId: number,
  type: metadataRequestSource,
) {
  const policy_hash = await getFQDNPolicy(fqdn);
  if (policy_hash.length === 0) {
    console.debug(`${url} is not enrolled, skipping...`);
    return;
  }

  if (type === metadataRequestSource.main_frame) {
    const newPopupState = new PopupState(fqdn, tabId, version, list_count);
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

  // Nothing can go wrong in this func anynmore hopefully, let's add the reference
  if (type === metadataRequestSource.main_frame) {
    tabs.set(tabId, fqdn);
  }

  // If origin metadata are already loaded, just skip doing it again and return early
  const originStateHolder = origins.get(fqdn);
  if (originStateHolder) {
    // Since we use cached info, we should still populate the popup with the cached info
    const popupState = popups.get(tabId);

    if (popupState) {
      popupState.valid_headers =
        // We want it undefined, because we have not verified it yet
        popupState.valid_manifest =
          originStateHolder.current.status === "verified_manifest"
            ? true
            : undefined;
      popupState.threshold = originStateHolder.current.policy?.threshold;
      popupState.valid_signers = originStateHolder.current.valid_signers
        ? originStateHolder.current.valid_signers
        : [];
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

  // Policy hash is checked at the top and then later again
  const newOriginState = new OriginStateInitial(sigstore, fqdn, policy_hash);
  origins.set(fqdn, new OriginStateHolder(newOriginState));

  // So, we cannot directly know that we are the initiator of this request, see
  // https://stackoverflow.com/questions/31129648/how-to-identify-who-initiated-the-http-request-in-firefox
  // It's tracked in the dev console, but no luck in extensions https://discourse.mozilla.org/t/access-webrequest-request-initiator-chain-stack-trace/75877
  // More sadness: https://stackoverflow.com/questions/47331875/webrequest-api-how-to-get-the-requestid-of-a-new-request
}
