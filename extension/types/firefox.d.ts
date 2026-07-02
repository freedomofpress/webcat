declare global {
  interface Window {
    /* eslint-disable @typescript-eslint/no-explicit-any */
    wrappedJSObject?: any;
  }
  interface Uint8Array {
    toBase64(options?: {
      alphabet?: "base64" | "base64url";
      omitPadding?: boolean;
    }): string;
  }
}

export {};
