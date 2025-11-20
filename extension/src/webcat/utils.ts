import { WebcatError } from "./interfaces/errors";

export function getFQDN(url: string): string {
  const urlobj = new URL(url);
  return urlobj.hostname;
}

export function getFQDNSafe(url: string): string {
  if (!/^https?:\/\//i.test(url)) {
    url = `https://${url}`;
  }
  return getFQDN(url);
}

export function isExtensionRequest(
  details: browser.webRequest._OnBeforeRequestDetails,
): boolean {
  return (
    details.originUrl !== undefined &&
    details.documentUrl !== undefined &&
    details.originUrl.substring(0, 16) === "moz-extension://" &&
    details.documentUrl.substring(0, 16) === "moz-extension://" &&
    details.tabId === -1
  );
}

export async function SHA256(
  data: ArrayBuffer | Uint8Array | string,
): Promise<ArrayBuffer> {
  let input: ArrayBuffer;

  if (typeof data === "string") {
    input = new TextEncoder().encode(data).buffer;
  } else if (data instanceof Uint8Array) {
    input = data.slice().buffer;
  } else {
    input = data;
  }

  return crypto.subtle.digest("SHA-256", input);
}

export function arraysEqual(a: Uint8Array, b: Uint8Array): boolean {
  if (a.length !== b.length) return false;
  for (let i = 0; i < a.length; i++) {
    if (a[i] !== b[i]) return false;
  }
  return true;
}

export async function errorpage(tabId: number, error?: WebcatError) {
  const code = error?.code ?? "WEBCAT_ERROR_UNDEFINED";
  const errorPageUrl = browser.runtime.getURL("pages/error.html");

  // Things that do not work:
  // - Creating a blob dynamically
  // - Rewriting the page without a redirect

  // Things that are nice to avoid
  // - Query/fragment parameter passing
  // - Messaging

  // Current solution is: navigate and then inject a conte script
  // Avoids messaging, scripts in the page itself, and weird urls

  // 1. Navigate to the error page
  await browser.tabs.update(tabId, { url: errorPageUrl });

  // 2. Wait until the extension page loads
  await new Promise<void>((resolve) => {
    const listener = (
      updatedTabId: number,
      changeInfo: browser.tabs._OnUpdatedChangeInfo,
    ) => {
      if (updatedTabId === tabId && changeInfo.status === "complete") {
        browser.tabs.onUpdated.removeListener(listener);
        resolve();
      }
    };
    browser.tabs.onUpdated.addListener(listener);
  });

  // 3. Dynamically inject a script *into the error page*
  await browser.tabs.executeScript(tabId, {
    code: `
      document.getElementById("error-code").textContent = ${JSON.stringify(code)};
    `,
  });
}
