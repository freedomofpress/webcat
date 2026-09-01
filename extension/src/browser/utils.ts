/**
 * @param fqdns An array of fully-qualified domain names.
 * @returns An array of {@link https://developer.mozilla.org/en-US/docs/Mozilla/Add-ons/WebExtensions/Match_patterns | patterns} that match the FQDNs.
 */
export function buildUrlPatterns(fqdns: string[]): string[] {
  const urls: string[] = [];
  for (const fqdn of fqdns) {
    urls.push(`http://${fqdn}/*`);
    urls.push(`https://${fqdn}/*`);
  }
  return urls;
}
