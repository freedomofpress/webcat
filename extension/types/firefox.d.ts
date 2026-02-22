declare global {
  interface Window {
    wrappedJSObject?: unknown;

    /* eslint-disable @typescript-eslint/no-explicit-any */
    exportFunction?<T extends (...args: any[]) => any>(
      fn: T,
      targetScope: object,
      options?: unknown,
    ): T;
  }
}

export {};
