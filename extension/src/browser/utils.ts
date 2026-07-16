export function buildUrlPatterns(fqdns: string[]): string[] {
  const urls: string[] = [];
  for (const fqdn of fqdns) {
    urls.push(`http://${fqdn}/*`);
    urls.push(`https://${fqdn}/*`);
  }
  return urls;
}
