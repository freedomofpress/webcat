import { BeforeRequestDetails } from "../browser/requests";
import { CacheKey } from "./cache";
import { Database } from "./interfaces/database";
import { WebcatError, WebcatErrorCode } from "./interfaces/errors";
import { Stateful } from "./interfaces/requeststate";
import { logger } from "./logger";
import {
  BundleFetcher,
  OriginStateHolder,
  OriginStateInitial,
} from "./originstate";
import { setIcon } from "./ui";

declare const __IS_TESTING__: boolean;

const allowedPorts = __IS_TESTING__ ? ["8080", "8443", ""] : ["80", "443", ""];

export function validateProtocolAndPort(urlobj: URL): boolean {
  if (
    !allowedPorts.includes(urlobj.port) ||
    !["http:", "https:"].includes(urlobj.protocol)
  ) {
    return false;
  } else {
    return true;
  }
}

export function enforceHTTPS(urlobj: URL): string | undefined {
  if (
    urlobj.protocol !== "https:" &&
    urlobj.hostname.substring(urlobj.hostname.lastIndexOf(".")) !== ".onion"
  ) {
    urlobj.protocol = "https:";
    if (__IS_TESTING__) {
      urlobj.port = "8443";
    }
    return urlobj.toString();
  }
}

export async function validateOrigin(
  db: Database,
  details: Stateful<BeforeRequestDetails>,
) {
  const { fqdn, cachePartition, isFrame } = details.state;
  const enrollment_hash = await db.getFQDNEnrollment(fqdn, cachePartition);
  if (enrollment_hash.length === 0) {
    //console.debug(`${url} is not enrolled, skipping...`);
    return;
  }

  if (isFrame) {
    setIcon(details.tabId);
  }

  // See https://github.com/freedomofpress/webcat/issues/1
  const urlobj = new URL(details.url);

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

  const cached = db.origins.get(CacheKey(fqdn, cachePartition));
  if (cached) {
    // Pin the holder to this request so later stages cannot race against LRU eviction
    details.state.pendingOrigin = cached;
    return;
  }

  // Generate a new state for the origin
  logger.info(`${fqdn} is enrolled, but we do not have metadata yet.`, details);

  // Policy hash is checked at the top and then later again
  const newFetcher = new BundleFetcher(
    `${urlobj.protocol}//${fqdn}:${urlobj.port}`,
  );
  const newOriginState = new OriginStateInitial(
    newFetcher,
    urlobj.protocol,
    urlobj.port,
    fqdn,
    enrollment_hash,
    cachePartition,
  );
  const origin = new OriginStateHolder(newOriginState);
  details.state.pendingOrigin = origin;

  // See https://github.com/freedomofpress/webcat/issues/95
  await origin.current.fetcher.awaitAll();

  return;

  // So, we cannot directly know that we are the initiator of this request, see
  // https://stackoverflow.com/questions/31129648/how-to-identify-who-initiated-the-http-request-in-firefox
  // It's tracked in the dev console, but no luck in extensions https://discourse.mozilla.org/t/access-webrequest-request-initiator-chain-stack-trace/75877
  // More sadness: https://stackoverflow.com/questions/47331875/webrequest-api-how-to-get-the-requestid-of-a-new-request
}
