export * from "../webcat/validators";

export const validateProtocolAndPort = (urlobj: URL) => {
  console.log(
    "[TESTING] validateProtocolAndPort hooked - using ports 8080 and 8443 for:",
    urlobj.href,
  );
  if (
    (urlobj.port === "8080" && urlobj.protocol === "http:") ||
    (urlobj.port === "8443" && urlobj.protocol === "https:")
  ) {
    return true;
  } else {
    return false;
  }
};

export function enforceHTTPS(urlobj: URL): string | undefined {
  console.log(
    "[TESTING] enforceHTTPS hooked - using port 8443 for:",
    urlobj.href,
  );
  if (
    urlobj.protocol !== "https:" &&
    urlobj.hostname.substring(urlobj.hostname.lastIndexOf(".")) !== ".onion"
  ) {
    urlobj.protocol = "https:";
    urlobj.port = "8443";
    return urlobj.toString();
  }
}

console.log("[TESTING] Mock validators module loaded");
