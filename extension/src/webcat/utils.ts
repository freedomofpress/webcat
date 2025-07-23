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

export async function SHA256(data: ArrayBuffer | Uint8Array | string) {
  // Sometimes we hash strings, such as the FQDN, sometimes we hash bytes, such as page content
  let inputData: Uint8Array | ArrayBuffer;
  if (typeof data === "string") {
    inputData = new TextEncoder().encode(data);
  } else {
    inputData = data;
  }
  const hash = await crypto.subtle.digest("SHA-256", inputData);

  return hash;
}

export function arrayBufferToHex(buffer: Uint8Array | ArrayBuffer) {
  const array = Array.from(new Uint8Array(buffer));
  return array.map((b) => b.toString(16).padStart(2, "0")).join("");
}

export function arraysEqual(a: Uint8Array, b: Uint8Array): boolean {
  if (a.length !== b.length) return false;
  for (let i = 0; i < a.length; i++) {
    if (a[i] !== b[i]) return false;
  }
  return true;
}

export function errorpage(tabId: number) {
  // TODO, what if the error happens in the background? We should probably hunt all tabs with
  // that main frame or subframe and error them
  if (tabId > 0) {
    browser.tabs.update(tabId, {
      url: browser.runtime.getURL("pages/error.html"),
    });
  }
}

// Will remove this as we develop and bundle into thre Sigsum package
// A native JSON format
// In the meantime
// eslint-disable-next-line @typescript-eslint/no-explicit-any
export function jsonToSigsumAscii(json: any): string {
  const lines: string[] = [];

  lines.push(`version=${json.version}`);
  lines.push(`log=${json.log_key_hash}`);
  lines.push(`leaf=${json.leaf.key_hash} ${json.leaf.signature}`);
  lines.push(`tree_size=${json.tree_head.size}`);
  lines.push(`root_hash=${json.tree_head.root_hash}`);
  lines.push(`signature=${json.tree_head.signature}`);

  if (Array.isArray(json.tree_head.cosignatures)) {
    for (const cosig of json.tree_head.cosignatures) {
      lines.push(
        `cosignature=${cosig.keyhash} ${cosig.timestamp} ${cosig.signature}`,
      );
    }
  }

  lines.push(`leaf_index=${json.inclusion_proof.leaf_index}`);
  for (const hash of json.inclusion_proof.node_hashes) {
    lines.push(`node_hash=${hash}`);
  }

  return lines.join("\n");
}
