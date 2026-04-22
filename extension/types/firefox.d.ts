declare global {
  interface Window {
    /* eslint-disable @typescript-eslint/no-explicit-any */
    wrappedJSObject?: any;
  }
  /* eslint-disable @typescript-eslint/no-unsafe-function-type */
  function exportFunction<T extends Function>(
    func: T,
    targetScope: object,
    options?: { defineAs?: string },
  ): T;
  interface Uint8Array {
    toBase64(options?: {
      alphabet?: "base64" | "base64url";
      omitPadding?: boolean;
    }): string;
  }
}

export {};
