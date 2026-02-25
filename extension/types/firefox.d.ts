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
}

export {};
