declare global {
  // eslint-disable-next-line @typescript-eslint/no-unsafe-function-type
  function exportFunction<T extends Function>(
    func: T,
    targetScope: object,
    options?: { defineAs?: string },
  ): T;
  // eslint-disable-next-line @typescript-eslint/no-namespace
  namespace XPCNativeWrapper {
    function unwrap<T>(obj: T): T;
  }
}

export type LocalScope<T> = Record<string, { data: T; ready: Promise<void> }>;

export const hooked = Symbol("WEBCAT");
export const global = globalThis.self || globalThis;
const isolated = typeof globalThis.exportFunction === "function";

export function unwrap<T>(object: T) {
  if (isolated) {
    return XPCNativeWrapper.unwrap(object);
  }
  return object;
}

// eslint-disable-next-line @typescript-eslint/no-unsafe-function-type
export function exportFunc<T extends Function>(
  func: T,
  object: object = global,
  prop: string | undefined = undefined,
) {
  if (isolated) {
    const options = {} as { defineAs?: string };
    if (prop !== undefined) {
      options.defineAs = prop;
    }
    return exportFunction(func, XPCNativeWrapper.unwrap(object), options);
  } else if (prop !== undefined) {
    (object as { [prop]: T })[prop] = func;
  }
  return func;
}

export function updatableHook<T extends { [index: string]: unknown }>(
  name: string,
  hook: (data: Promise<T>, scope: { data: T; ready: Promise<void> }) => void,
) {
  return function (scopeObject: object, data: string | T) {
    const scope = scopeObject as { hooks?: LocalScope<T> };
    if (!scope.hooks) {
      scope.hooks = {};
    }

    // Check if the hook has already been injected.
    if (name in scope.hooks) {
      console.log(`[WEBCAT] Hook already injected: ${name}`);
      scope.hooks[name].data = data as T; // update data
      return;
    }

    // Allow updating data through localScope
    const { promise: ready, resolve } = global.Promise.withResolvers<void>();
    scope.hooks[name] = { ready, data: data as T };
    Object.defineProperty(scope.hooks[name], "data", {
      set: (v) => {
        data = v;
        resolve();
      },
      get: () => data,
    });
    if (typeof data === "object") {
      scope.hooks[name].data = data as T;
    }

    hook(
      ready.then(() => data as T),
      scope.hooks[name],
    );
  };
}
