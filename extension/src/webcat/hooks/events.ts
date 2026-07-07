import { exportFunc, global, hooked, unwrap, updatableHook } from "./core";

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
