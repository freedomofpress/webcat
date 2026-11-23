// Firefox 153+; absent on older versions. Drop once @types/firefox-webext-browser covers it.
declare namespace browser.publicSuffix {
  function getDomain(hostname: string): string | null;
}
