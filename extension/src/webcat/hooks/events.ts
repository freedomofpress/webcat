import {
  EventListenerArgs,
  EventListenerArgsByKind,
  exportFunc,
  global,
  Hooked,
  hooked,
  Internal,
  internal,
  unwrap,
  updatableHook,
} from "./core";

// Map.prototype.getOrInsert is not yet available in Firefox ESR & TBB
// https://developer.mozilla.org/en-US/docs/Web/JavaScript/Reference/Global_Objects/Map/getOrInsert
function getOrInsert<M extends Map<K, V>, K, V>(
  map: M,
  key: K,
  defaultValue: V,
) {
  if (map.has(key)) {
    return map.get(key) as V;
  }
  map.set(key, defaultValue);
  return defaultValue;
}

function bindEventListenerArgs<T extends EventTarget>(
  thisArg: Hooked<T, Internal<T>>,
  args: EventListenerArgs,
) {
  const callback = unwrap(args[1]);
  args = Array.from(args) as EventListenerArgs;
  if (typeof callback === "function") {
    args[1] = callback.bind(thisArg);
  } else {
    args[1] = exportFunc(
      (...args: [event: Event]) => callback.handleEvent?.call(thisArg, ...args),
      global,
    ) as EventListener;
  }
  return args;
}

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
 * Connects the event listeners on a hooked object to the native object
 */
export function connectEventListeners<T extends EventTarget>(
  target: Hooked<T, Internal<T>>,
) {
  const props = Object.keys(target[internal]).filter((k) => k.startsWith("on"));
  for (const prop of props) {
    type P = { [prop]: (...args: unknown[]) => unknown | null };
    (target[internal].instance as unknown as P)[prop] =
      (target[internal] as Internal<T> & P)[prop]?.bind(target) || null;
  }
  for (const listeners of target[internal].listeners.values()) {
    for (const { nonCapturingArgs, capturingArgs } of listeners.values()) {
      if (nonCapturingArgs) {
        target[internal].instance.addEventListener(...nonCapturingArgs);
      }
      if (capturingArgs) {
        target[internal].instance.addEventListener(...capturingArgs);
      }
    }
  }
}

/**
 * Hooks EventTarget to support hooked objects
 */
export const eventTargetHook = updatableHook("EventTarget", function () {
  // Hook EventTarget.addEventListener
  const { value: originalAddEventListener } = Object.getOwnPropertyDescriptor(
    unwrap(global.EventTarget.prototype),
    "addEventListener",
  ) as PropertyDescriptor;
  function hookedAddEventListener(
    this: Hooked<EventTarget, Internal<EventTarget>>,
    ...args: EventListenerArgs
  ) {
    const [type, callback, options] = args;
    if (internal in unwrap(this)) {
      const listeners = getOrInsert(
        getOrInsert(unwrap(this)[internal].listeners, type, new Map()),
        callback,
        {} as EventListenerArgsByKind,
      );
      const useCapture =
        options instanceof window.Object
          ? !!unwrap(options).capture
          : !!unwrap(options);
      const kind = useCapture ? "capturingArgs" : "nonCapturingArgs";
      if (!listeners[kind]) {
        // Listener doesn't exist; bind args and memorize
        const boundArgs = bindEventListenerArgs(unwrap(this), args);
        listeners[kind] = boundArgs;
        if (unwrap(this)[internal].instance) {
          // Instance exists, add the listener for real
          unwrap(this)[internal].instance.addEventListener(...boundArgs);
        }
      }
    } else {
      originalAddEventListener.call(this, ...args);
    }
  }
  Object.defineProperty(
    unwrap(global.EventTarget.prototype),
    "addEventListener",
    {
      value: exportFunc(hookedAddEventListener, global),
    },
  );

  // Hook EventTarget.removeEventListener
  const { value: originalRemoveEventListener } =
    Object.getOwnPropertyDescriptor(
      unwrap(global.EventTarget.prototype),
      "removeEventListener",
    ) as PropertyDescriptor;
  function hookedRemoveEventListener(
    this: Hooked<EventTarget, Internal<EventTarget>>,
    ...args: EventListenerArgs
  ) {
    const [type, callback, options] = args;
    if (internal in unwrap(this)) {
      const listeners = getOrInsert(
        getOrInsert(unwrap(this)[internal].listeners, type, new Map()),
        callback,
        {} as EventListenerArgsByKind,
      );
      const useCapture =
        options instanceof window.Object
          ? !!unwrap(options).capture
          : !!unwrap(options);
      const kind = useCapture ? "capturingArgs" : "nonCapturingArgs";
      if (listeners[kind]) {
        // Listener exists; remove
        if (unwrap(this)[internal].instance) {
          // Instance exists, remove for real
          unwrap(this)[internal].instance.removeEventListener(
            ...listeners[kind],
          );
        }
        delete listeners[kind];
      }
    } else {
      originalRemoveEventListener.call(this, ...args);
    }
  }
  Object.defineProperty(
    unwrap(global.EventTarget.prototype),
    "removeEventListener",
    {
      value: exportFunc(hookedRemoveEventListener, global),
    },
  );

  // Hook EventTarget.dispatchEvent
  const { value: originalDispatchEvent } = Object.getOwnPropertyDescriptor(
    unwrap(global.EventTarget.prototype),
    "dispatchEvent",
  ) as PropertyDescriptor;
  function hookedDispatchEvent(
    this: Hooked<EventTarget, Internal<EventTarget>>,
    ...args: [event: Event]
  ) {
    if (internal in unwrap(this)) {
      if (unwrap(this)[internal].instance) {
        return unwrap(this)[internal].instance.dispatchEvent(...args);
      }
      // TODO: handle synchronous case
      return true;
    }
    return originalDispatchEvent.call(this, ...args);
  }
  Object.defineProperty(unwrap(global.EventTarget.prototype), "dispatchEvent", {
    value: exportFunc(hookedDispatchEvent, global),
  });
});

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
