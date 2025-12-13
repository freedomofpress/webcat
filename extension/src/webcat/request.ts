import { origins, tabs } from "./../globals";
import { db } from "./../globals";
import { metadataRequestSource } from "./interfaces/base";
import { WebcatError, WebcatErrorCode } from "./interfaces/errors";
import {
  OriginStateHolder,
  OriginStateInitial,
} from "./interfaces/originstate";
import { logger } from "./logger";
import { NON_FRAME_TYPES } from "./resources";
import { setIcon } from "./ui";
import { enforceHTTPS, validateProtocolAndPort } from "./validators";

export async function validateOrigin(
  fqdn: string,
  url: string,
  tabId: number,
  type: metadataRequestSource,
) {
  const enrollment_hash = await db.getFQDNEnrollment(fqdn);
  if (enrollment_hash.length === 0) {
    //console.debug(`${url} is not enrolled, skipping...`);
    return;
  }

  if (type === metadataRequestSource.main_frame) {
    setIcon(tabId);
  }

  // See https://github.com/freedomofpress/webcat/issues/1
  const urlobj = new URL(url);

  if (!validateProtocolAndPort(urlobj)) {
    return new WebcatError(WebcatErrorCode.URL.UNSUPPORTED, [
      String(urlobj.protocol),
      String(urlobj.port || "default"),
    ]);
  }

  const redirect = enforceHTTPS(urlobj);
  if (redirect) {
    return { redirectUrl: redirect };
  }

  // Nothing can go wrong in this func anymore hopefully, let's add the reference
  if (type === metadataRequestSource.main_frame) {
    tabs.set(tabId, fqdn);
  }

  // If origin metadata are already loaded, just skip doing it again and return early
  const originStateHolder = origins.get(fqdn);
  if (originStateHolder) {
    // Since we use cached info, we should still populate the popup with the cached info
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
  const newOriginState = new OriginStateInitial(
    urlobj.protocol,
    urlobj.port,
    fqdn,
    enrollment_hash,
  );
  const origin = new OriginStateHolder(newOriginState);
  origins.set(fqdn, origin);

  // We want to intercept everything for enrolled wbesites
  browser.webRequest.onBeforeRequest.addListener(
    origin.current.onBeforeRequest,
    {
      urls: [`http://${fqdn}/*`, `https://${fqdn}/*`],
      types: NON_FRAME_TYPES,
    },
    ["blocking"],
  );

  browser.webRequest.onHeadersReceived.addListener(
    origin.current.onHeadersReceived,
    {
      urls: [`http://${fqdn}/*`, `https://${fqdn}/*`],
      types: NON_FRAME_TYPES,
    },
    ["blocking", "responseHeaders"],
  );

  return;

  // So, we cannot directly know that we are the initiator of this request, see
  // https://stackoverflow.com/questions/31129648/how-to-identify-who-initiated-the-http-request-in-firefox
  // It's tracked in the dev console, but no luck in extensions https://discourse.mozilla.org/t/access-webrequest-request-initiator-chain-stack-trace/75877
  // More sadness: https://stackoverflow.com/questions/47331875/webrequest-api-how-to-get-the-requestid-of-a-new-request
}
