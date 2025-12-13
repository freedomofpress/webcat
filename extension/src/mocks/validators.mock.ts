export * from "../webcat/validators";

export const validateProtocolAndPort = (_url: URL) => {
  console.log(
    "[TESTING] validateProtocolAndPort hooked - always returning true for:",
    _url.href,
  );
  return true;
};

export const enforceHTTPS = (_url: URL) => {
  console.log(
    "[TESTING] enforceHTTPS hooked - skipping HTTPS enforcement for:",
    _url.href,
  );
  return undefined;
};

console.log("[TESTING] Mock validators module loaded");
