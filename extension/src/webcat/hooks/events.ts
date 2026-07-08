import {
  exportFunc,
  global,
  Hooked,
  hooked,
  Internal,
  internal,
  unwrap,
  updatableHook,
} from "./core";

/**
 * Hooks an event property such as onerror or onmessage and handles assignment
 * to an internal instance in a hooked object
 */
export function hookEventProperty<T extends object, I extends Internal<T>>(
  prototype: object,
  prop: string,
) {
  const { get: originalGetProp, set: originalSetProp } =
    Object.getOwnPropertyDescriptor(prototype, prop) as PropertyDescriptor;
  function hookedGetProp(this: Hooked<T, I>) {
    if (internal in unwrap(this)) {
      return (unwrap(this)[internal] as { [prop]: unknown })[prop];
    }
    return originalGetProp?.call(this);
  }
  function hookedSetProp(
    this: Hooked<T, I>,
    v: (...args: unknown[]) => unknown,
  ) {
    if (internal in unwrap(this)) {
      (unwrap(this)[internal] as { [prop]: unknown })[prop] = v;
      if (unwrap(this)[internal].instance) {
        (unwrap(this)[internal].instance as { [prop]: unknown })[prop] =
          v?.bind(unwrap(this)) || null;
      }
    } else {
      originalSetProp?.call(this, v);
    }
  }
  Object.defineProperty(prototype, prop, {
    get: exportFunc(hookedGetProp, global) as () => unknown,
    set: exportFunc(hookedSetProp, global) as (v: unknown) => void,
  });
}

/**
 * Hooks the Event prototype to return hooked targets
 */
export const eventHook = updatableHook("Event", function () {
  for (const prop of [
    "target",
    "currentTarget",
    "originalTarget",
    "explicitOriginalTarget",
    "srcElement",
  ]) {
    const { get: originalGet } = Object.getOwnPropertyDescriptor(
      unwrap(global.Event.prototype),
      prop,
    ) as PropertyDescriptor;
    function hookedGet(this: Event) {
      const val = unwrap(originalGet?.call(this));
      return val?.[hooked] || val;
    }
    Object.defineProperty(unwrap(global.Event.prototype), prop, {
      get: exportFunc(hookedGet, global) as () => unknown,
    });
  }
});
