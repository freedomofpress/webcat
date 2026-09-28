import {
  apply,
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

// Normalize the third argument of add/removeEventListener. Per WebIDL it may
// be a dictionary (any object, including a callable), a boolean, null or
// undefined.
function optionsOf(options?: EventListenerArgs[2]): AddEventListenerOptions {
  const o = unwrap(options);
  return o && (typeof o === "object" || typeof o === "function")
    ? o
    : { capture: !!o };
}

// Bind fn to target without going through the page's Function.prototype.bind
function bindTo(fn: (...args: unknown[]) => unknown, target: object) {
  return exportFunc((...e: unknown[]) => apply(fn, target, e));
}

function bindEventListenerArgs<T extends EventTarget>(
  thisArg: Hooked<T, Internal<T>>,
  args: EventListenerArgs,
  listeners: EventListenerArgsByKind,
  kind: keyof EventListenerArgsByKind,
) {
  const callback = unwrap(args[1]);
  const { once } = optionsOf(args[2]);
  args[1] = exportFunc((...e: [Event]) => {
    // The native dispatcher already removed the once listener. Only retire
    // this registration's bookkeeping, before invoking user code.
    if (once && listeners[kind] === args) {
      delete listeners[kind];
    }
    // handleEvent is resolved at dispatch time and, like function callbacks,
    // invoked with the hooked target as this (the integration tests rely on
    // event.target === this for both forms)
    const fn =
      typeof callback === "function" ? callback : callback?.handleEvent;
    return fn && apply(fn, thisArg, e);
  }) as EventListener;
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
    return originalGetProp && apply(originalGetProp, this, []);
  }
  function hookedSetProp(
    this: Hooked<T, I>,
    v: (...args: unknown[]) => unknown,
  ) {
    if (internal in unwrap(this)) {
      (unwrap(this)[internal] as { [prop]: unknown })[prop] = v;
      if (unwrap(this)[internal].instance) {
        (unwrap(this)[internal].instance as { [prop]: unknown })[prop] =
          typeof v === "function" ? bindTo(v, unwrap(this)) : null;
      }
    } else {
      if (originalSetProp) {
        apply(originalSetProp, this, [v]);
      }
    }
  }
  Object.defineProperty(prototype, prop, {
    get: exportFunc(hookedGetProp) as () => unknown,
    set: exportFunc(hookedSetProp) as (v: unknown) => void,
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
    type P = { [prop]: ((...args: unknown[]) => unknown) | null };
    const fn = (target[internal] as Internal<T> & P)[prop];
    (target[internal].instance as unknown as P)[prop] =
      typeof fn === "function" ? bindTo(fn, target) : null;
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
    if (this && internal in unwrap(this)) {
      // WebIDL reads dictionary members once, at registration time. Keep
      // that snapshot even when connecting the backing instance later.
      const { capture, once, passive, signal } = optionsOf(options);
      // Native calls through exported hooks need a page-realm dictionary.
      const normalizedOptions = unwrap(
        new global.Object(),
      ) as AddEventListenerOptions;
      normalizedOptions.capture = !!capture;
      normalizedOptions.once = !!once;
      normalizedOptions.passive = passive === undefined ? undefined : !!passive;
      normalizedOptions.signal = signal;
      const listeners = getOrInsert(
        getOrInsert(unwrap(this)[internal].listeners, type, new Map()),
        callback,
        {} as EventListenerArgsByKind,
      );
      const kind = capture ? "capturingArgs" : "nonCapturingArgs";
      const oldArgs = listeners[kind];
      if (!oldArgs || optionsOf(oldArgs[2]).signal?.aborted) {
        // Listener doesn't exist; bind args and memorize
        const boundArgs = bindEventListenerArgs(
          unwrap(this),
          [type, callback, normalizedOptions],
          listeners,
          kind,
        );
        listeners[kind] = boundArgs;
        if (unwrap(this)[internal].instance) {
          // Instance exists, add the listener for real
          unwrap(this)[internal].instance.addEventListener(...boundArgs);
        }
      }
    } else {
      apply(originalAddEventListener, this, args);
    }
  }
  Object.defineProperty(
    unwrap(global.EventTarget.prototype),
    "addEventListener",
    {
      value: exportFunc(hookedAddEventListener),
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
    if (this && internal in unwrap(this)) {
      const listeners = unwrap(this)
        [internal].listeners.get(type)
        ?.get(callback);
      const kind = optionsOf(options).capture
        ? "capturingArgs"
        : "nonCapturingArgs";
      if (listeners?.[kind]) {
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
      apply(originalRemoveEventListener, this, args);
    }
  }
  Object.defineProperty(
    unwrap(global.EventTarget.prototype),
    "removeEventListener",
    {
      value: exportFunc(hookedRemoveEventListener),
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
    if (this && internal in unwrap(this)) {
      if (unwrap(this)[internal].instance) {
        return unwrap(this)[internal].instance.dispatchEvent(...args);
      }
      // TODO: handle synchronous case
      return true;
    }
    return apply(originalDispatchEvent, this, args);
  }
  Object.defineProperty(unwrap(global.EventTarget.prototype), "dispatchEvent", {
    value: exportFunc(hookedDispatchEvent),
  });
});

/**
 * Hooks the Event prototype to return hooked targets
 */
export const eventHook = updatableHook("Event", function () {
  // Hook Event target getters
  for (const prop of [
    "target",
    "currentTarget",
    "originalTarget",
    "explicitOriginalTarget",
    "srcElement",
  ]) {
    const { get: originalGet } =
      Object.getOwnPropertyDescriptor(unwrap(global.Event.prototype), prop) ??
      {};
    if (!originalGet) {
      continue;
    }
    function hookedGet(this: Event) {
      const val = unwrap(apply(originalGet, this, []));
      return val?.[hooked] ?? val;
    }
    Object.defineProperty(unwrap(global.Event.prototype), prop, {
      get: exportFunc(hookedGet) as () => unknown,
    });
  }

  // Hook Event.composedPath
  const { value: originalComposedPath } = Object.getOwnPropertyDescriptor(
    unwrap(global.Event.prototype),
    "composedPath",
  ) as { value: Event["composedPath"] };
  function hookedComposedPath(this: Event) {
    const path = unwrap(apply(originalComposedPath, this, []));
    // Index access only: iterator and entries() resolve on the page's
    // Array.prototype and would expose the raw path before it's rewritten
    for (let i = 0; i < path.length; i++) {
      const val = path[i];
      path[i] = val?.[hooked] ?? val;
    }
    return path;
  }
  Object.defineProperty(unwrap(global.Event.prototype), "composedPath", {
    value: exportFunc(hookedComposedPath),
  });
});
