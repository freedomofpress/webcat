import { OriginState } from "./interfaces";
import { isExtensionRequest, isFQDNEnrolled, isHTTPS, isOnion, isRoot } from "./utils";
import { setIcon, setErrorIcon } from "./ui";

export async function validateMainFrame(
  tabs: Map<number, string>,
  origins: Map<string, OriginState>,
  fqdn: string,
  url: string,
  tabId: number,
) {
  if ((await isFQDNEnrolled(fqdn)) === false) {
    console.log(`${url} is not enrolled, skipping...`);
    return;
  }

  // If the website is enrolled but is loading via HTTP abort anyway
  // Or maybe not if it's an onion website :)
  if (isHTTPS(url) === false && isOnion(url) === false) {
    setErrorIcon(tabId);
    throw new Error(
      "Attempting to load HTTP resource for a non-onion enrolled FQDN!",
    );
  }

  // Do we care about this? What matters in the end is the main_frame context
  if (isRoot(url) === false) {
    setErrorIcon(tabId);
    throw new Error("Enrolled applications should be loaded from the root.");
  }

  // Nothing can go wrong in this func anynmore hopefully, let's add the reference
  tabs.set(tabId, fqdn);

  // If origin metadata are already loaded, just skip doing it again and return early
  if (origins.has(fqdn)) {
    return;
  }

  // Generate a new state for the origin
  console.log(`${fqdn} is enrolled, but we do not have metadata yet.`);
  const newOriginState = new OriginState();
  origins.set(fqdn, newOriginState);

  // So, we cannot directly know that we are the initiator of this request, see
  // https://stackoverflow.com/questions/31129648/how-to-identify-who-initiated-the-http-request-in-firefox
  // It's tracked in the dev console, but no luck in extensions https://discourse.mozilla.org/t/access-webrequest-request-initiator-chain-stack-trace/75877
  // More sadness: https://stackoverflow.com/questions/47331875/webrequest-api-how-to-get-the-requestid-of-a-new-request
  console.log(`Fetching https://${fqdn}/manifest.json`);
  newOriginState.manifestPromise = fetch(`https://${fqdn}/manifest.json`, {
    cache: "no-store",
  });
}
