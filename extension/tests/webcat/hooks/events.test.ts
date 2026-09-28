import { afterEach, beforeEach, describe, expect, it, vi } from "vitest";

import {
  Hooked,
  hooked,
  Internal,
  internal,
  makeInternal,
} from "../../../src/webcat/hooks/core";
import {
  connectEventListeners,
  eventHook,
  eventTargetHook,
  hookEventProperty,
} from "../../../src/webcat/hooks/events";

afterEach(() => {
  vi.resetAllMocks();
  vi.unstubAllGlobals();
});

describe("eventHook", () => {
  beforeEach(() => {
    class EventStub extends Event {}
    Object.defineProperties(
      EventStub.prototype,
      Object.getOwnPropertyDescriptors(Event.prototype),
    );
    vi.stubGlobal("Event", EventStub);
  });

  it("prevents access to unhooked values of hooked targets", () => {
    eventHook({}, {});

    // Construct a target in the expected shape
    const target = new (class extends EventTarget {
      [hooked]: Hooked<EventTarget, Internal<EventTarget>>;
      constructor() {
        super();
        this[hooked] = new (class extends EventTarget {
          [internal] = makeInternal<EventTarget, object>({});
        })();
        this[hooked][internal].instance = this;
      }
    })();

    // Set up a listener and trigger it; only the hooked target is expected
    // to be accessible without knowledge of the internal symbol
    target.addEventListener("bonk", (event) => {
      for (const k in event) {
        if (event[k as keyof Event] instanceof EventTarget) {
          const targetFromEvent = event[k as keyof Event] as Hooked<
            EventTarget,
            Internal<EventTarget>
          >;
          expect(targetFromEvent).not.toBe(target);
          expect(targetFromEvent[internal].instance).toBe(target);
        }
      }
      expect(event.composedPath()).toStrictEqual([target[hooked]]);
    });
    const event = new Event("bonk");
    target.dispatchEvent(event);
  });

  it("allows access to unhooked targets", () => {
    eventHook({}, {});
    const event = new Event("bonk");
    const target = new EventTarget();
    target.addEventListener("bonk", (event) => {
      for (const k in event) {
        if (
          [
            "target",
            "currentTarget",
            "originalTarget",
            "explicitOriginalTarget",
            "srcElement",
          ].includes(k)
        ) {
          expect(event[k as keyof Event]).toBe(target);
        }
      }
      expect(event.composedPath()).toStrictEqual([target]);
    });
    target.dispatchEvent(event);
  });

  it("does not expose raw paths through page-controlled native helpers", () => {
    const composedPath = Event.prototype.composedPath;
    const getTarget = Object.getOwnPropertyDescriptor(
      Event.prototype,
      "target",
    )?.get;
    eventHook({}, {});
    const wrapper = new EventTarget();
    const target = Object.assign(new EventTarget(), { [hooked]: wrapper });
    let leaked = false;
    let nativeCalls = 0;
    let path: EventTarget[] = [];
    let eventTarget: EventTarget | null = null;

    target.addEventListener("bonk", (event) => {
      const call = Function.prototype.call;
      const entries = Array.prototype.entries;
      const iterator = Array.prototype[Symbol.iterator];
      Function.prototype.call = function (this: unknown, ...args: unknown[]) {
        if (this === composedPath || this === getTarget) nativeCalls++;
        return Reflect.apply(call, this, args);
      };
      Array.prototype.entries = function () {
        if (this[0] === target) leaked = true;
        return Reflect.apply(entries, this, []);
      };
      Array.prototype[Symbol.iterator] = function () {
        if (this[0] === target) leaked = true;
        return Reflect.apply(iterator, this, []);
      };
      try {
        path = event.composedPath();
        eventTarget = event.target;
      } finally {
        Function.prototype.call = call;
        Array.prototype.entries = entries;
        Array.prototype[Symbol.iterator] = iterator;
      }
    });

    target.dispatchEvent(new Event("bonk"));
    expect(path).toEqual([wrapper]);
    expect(eventTarget).toBe(wrapper);
    expect(leaked).toBe(false);
    expect(nativeCalls).toBe(0);
  });
});

describe("eventTargetHook", () => {
  beforeEach(() => {
    class EventTargetStub extends EventTarget {}
    Object.defineProperties(
      EventTargetStub.prototype,
      Object.getOwnPropertyDescriptors(EventTarget.prototype),
    );
    vi.stubGlobal("EventTarget", EventTargetStub);
  });

  it("does not interfere with normal EventTargets", () => {
    eventTargetHook({}, {});
    const target = new (class extends EventTarget {})();
    const onbonk = vi.fn();
    target.addEventListener("bonk", onbonk, true);
    target.addEventListener("bonk", onbonk, false);
    const bonkHandler = { handleEvent: vi.fn() };
    target.addEventListener("bonk", bonkHandler, false);
    target.addEventListener("bonk", bonkHandler, true);
    target.removeEventListener("bonk", onbonk);
    target.dispatchEvent(new Event("bonk"));
    target.removeEventListener("bonk", bonkHandler, { capture: true });
    target.addEventListener("bonk", onbonk);
    target.dispatchEvent(new Event("bonk"));

    const onbonkCallOrder = onbonk.mock.invocationCallOrder;
    const bonkHandlerCallOrder =
      bonkHandler.handleEvent.mock.invocationCallOrder;
    expect(onbonkCallOrder.length).toBe(3);
    expect(bonkHandlerCallOrder.length).toBe(3);

    // Note: Node doesn't respect useCapture, hence the order below. In a
    // browser the order would be different.
    const firstCall = Math.min(onbonkCallOrder[0], bonkHandlerCallOrder[0]);
    expect(onbonkCallOrder[0]).toBe(firstCall);
    expect(bonkHandlerCallOrder[0]).toBe(firstCall + 1);
    expect(bonkHandlerCallOrder[1]).toBe(firstCall + 2);
    expect(onbonkCallOrder[1]).toBe(firstCall + 3);
    expect(bonkHandlerCallOrder[2]).toBe(firstCall + 4);
    expect(onbonkCallOrder[2]).toBe(firstCall + 5);
  });

  it("does not interfere with the once and signal options", () => {
    eventTargetHook({}, {});
    const target = new (class extends EventTarget {})();
    const onbonkOnce = vi.fn();
    target.addEventListener("bonk", onbonkOnce, { once: true });
    target.dispatchEvent(new Event("bonk"));
    target.dispatchEvent(new Event("bonk"));
    expect(onbonkOnce).toHaveBeenCalledOnce();

    const onbonkWithAbort = vi.fn();
    const controller = new AbortController();
    target.addEventListener("bonk", onbonkWithAbort, {
      signal: controller.signal,
    });
    target.dispatchEvent(new Event("bonk"));
    target.dispatchEvent(new Event("bonk"));
    controller.abort();
    target.dispatchEvent(new Event("bonk"));
    expect(onbonkWithAbort.mock.calls.length).toBe(2);
  });

  it("tracks listeners in the internal object", () => {
    eventTargetHook({}, {});
    const target = new (class extends EventTarget {
      [internal] = makeInternal({});
    })();
    const onbonk = vi.fn();

    target.addEventListener("bonk", onbonk, true);
    target.addEventListener("bonk", onbonk, false);
    const bonkHandler = { handleEvent: vi.fn() };
    target.addEventListener("bonk", bonkHandler, false);
    target.addEventListener("bonk", bonkHandler, true);
    target.addEventListener("bonk", bonkHandler, { capture: true });

    {
      const l = target[internal].listeners;
      const bl = l.get("bonk");
      expect(l.size).toBe(1);
      expect(bl?.size).toBe(2);
      expect(bl?.get(onbonk)?.capturingArgs?.length).toBe(3);
      expect(bl?.get(onbonk)?.nonCapturingArgs?.length).toBe(3);
      expect(bl?.get(bonkHandler)?.capturingArgs?.length).toBe(3);
      expect(bl?.get(bonkHandler)?.nonCapturingArgs?.length).toBe(3);
      expect(bl?.get(bonkHandler)?.capturingArgs?.[2]).toMatchObject({
        capture: true,
      });
    }

    target.removeEventListener("bonk", onbonk);
    target.removeEventListener("bonk", bonkHandler, { capture: true });
    target.addEventListener("bonk", onbonk);

    const never = vi.fn();
    target.removeEventListener("bonk", never);

    {
      const l = target[internal].listeners;
      const bl = l.get("bonk");
      expect(l.size).toBe(1);
      expect(bl?.size).toBe(2);
      expect(bl?.get(onbonk)?.capturingArgs?.length).toBe(3);
      expect(bl?.get(onbonk)?.nonCapturingArgs?.length).toBe(3);
      expect(bl?.get(bonkHandler)?.capturingArgs).toBe(undefined);
      expect(bl?.get(bonkHandler)?.nonCapturingArgs?.length).toBe(3);
      expect(bl?.has(never)).toBe(false);
    }
  });

  it("calls listeners when events are dispatched on the backing instance", () => {
    eventTargetHook({}, {});
    const target = new (class extends EventTarget {
      [internal] = makeInternal({
        instance: new EventTarget(),
      });
    })();
    const onbonk1 = vi.fn();
    const onbonk2 = vi.fn();
    const onbonk3 = vi.fn();
    const onbonk4 = vi.fn();
    const handleBonk = {
      handleEvent: vi.fn(),
    };
    target.addEventListener("bonk", onbonk1);
    target.addEventListener("bonk", onbonk2);
    target.addEventListener("bonk", onbonk3, true);
    target.addEventListener("bonk", onbonk4, { capture: true });
    target.addEventListener("bonk", handleBonk);
    target.removeEventListener("bonk", onbonk2);
    const event = new Event("bonk");
    target[internal].instance.dispatchEvent(event);
    expect(onbonk1).toHaveBeenCalledExactlyOnceWith(event);
    expect(onbonk2).not.toHaveBeenCalled();
    expect(onbonk3).toHaveBeenCalledExactlyOnceWith(event);
    expect(onbonk4).toHaveBeenCalledExactlyOnceWith(event);
    expect(handleBonk.handleEvent).toHaveBeenCalledExactlyOnceWith(event);

    // Note: Node doesn't respect useCapture, hence the order below. In a
    // browser the order would be different.
    const firstCall = Math.min(
      onbonk1.mock.invocationCallOrder[0],
      onbonk3.mock.invocationCallOrder[0],
      onbonk4.mock.invocationCallOrder[0],
      handleBonk.handleEvent.mock.invocationCallOrder[0],
    );
    expect(onbonk1.mock.invocationCallOrder[0]).toBe(firstCall);
    expect(onbonk3.mock.invocationCallOrder[0]).toBe(firstCall + 1);
    expect(onbonk4.mock.invocationCallOrder[0]).toBe(firstCall + 2);
    expect(handleBonk.handleEvent.mock.invocationCallOrder[0]).toBe(
      firstCall + 3,
    );
  });

  it("allows dispatching events when an instance is available", () => {
    eventTargetHook({}, {});
    const target = new (class extends EventTarget {
      [internal] = makeInternal({
        instance: new EventTarget(),
      });
    })();
    const listener = vi.fn();
    target.addEventListener("bonk", listener);

    target.dispatchEvent(new Event("bonk"));
    expect(listener).toHaveBeenCalledOnce();

    // FIXME: The event should also be dispatched when the instance is not yet
    // available. Currently that's not the case, hence no second listener call
    // below.
    target[internal].instance = undefined as unknown as EventTarget;
    target.dispatchEvent(new Event("bonk"));
    expect(listener).toHaveBeenCalledOnce();
  });

  it("accepts null as options", () => {
    eventTargetHook({}, {});
    const target = new (class extends EventTarget {
      [internal] = makeInternal({ instance: new EventTarget() });
    })();
    const onbonk = vi.fn();
    target.addEventListener("bonk", onbonk, null as unknown as boolean);
    target.dispatchEvent(new Event("bonk"));
    target.removeEventListener("bonk", onbonk, null as unknown as boolean);
    target.dispatchEvent(new Event("bonk"));
    expect(onbonk).toHaveBeenCalledOnce();
  });

  it("correctly tracks listeners with the once option", () => {
    eventTargetHook({}, {});
    const target = new (class extends EventTarget {
      [internal] = makeInternal({
        instance: new EventTarget(),
      });
    })();
    const onbonk = vi.fn();
    const bonkHandler = { handleEvent: vi.fn() };
    target.addEventListener("bonk", onbonk, { once: true });
    target.addEventListener("bonk", bonkHandler, { once: true });

    // Dispatching an event twice should only result in one listener call
    target.dispatchEvent(new Event("bonk"));
    target.dispatchEvent(new Event("bonk"));
    expect(onbonk).toHaveBeenCalledOnce();
    expect(bonkHandler.handleEvent).toHaveBeenCalledOnce();

    // Re-adding the listener and dispatching should trigger another call
    target.addEventListener("bonk", onbonk);
    target.addEventListener("bonk", bonkHandler);
    target.dispatchEvent(new Event("bonk"));
    expect(onbonk.mock.calls.length).toBe(2);
    expect(bonkHandler.handleEvent.mock.calls.length).toBe(2);
  });

  it("correctly tracks listeners with the signal option", () => {
    eventTargetHook({}, {});
    const target = new (class extends EventTarget {
      [internal] = makeInternal({
        instance: new EventTarget(),
      });
    })();
    const onbonk = vi.fn();
    const bonkHandler = { handleEvent: vi.fn() };
    const controller = new AbortController();
    target.addEventListener("bonk", onbonk, { signal: controller.signal });
    target.addEventListener("bonk", bonkHandler, { signal: controller.signal });

    // Dispatching an event twice should only result in two listener calls
    target.dispatchEvent(new Event("bonk"));
    target.dispatchEvent(new Event("bonk"));
    expect(onbonk.mock.calls.length).toBe(2);
    expect(bonkHandler.handleEvent.mock.calls.length).toBe(2);

    // Dispatching after abort should result in no additional calls
    controller.abort();
    target.dispatchEvent(new Event("bonk"));
    expect(onbonk.mock.calls.length).toBe(2);
    expect(bonkHandler.handleEvent.mock.calls.length).toBe(2);

    // Re-adding the listener and dispatching should trigger another call
    target.addEventListener("bonk", onbonk);
    target.addEventListener("bonk", bonkHandler);
    target.dispatchEvent(new Event("bonk"));
    expect(onbonk.mock.calls.length).toBe(3);
    expect(bonkHandler.handleEvent.mock.calls.length).toBe(3);
  });

  it("retires once bookkeeping before callbacks without public removal", () => {
    eventTargetHook({}, {});
    const target = new (class extends EventTarget {
      [internal] = makeInternal({ instance: new EventTarget() });
    })();
    target.removeEventListener = vi.fn(() => {
      throw new Error("Public removal must not run during once cleanup");
    });
    let calls = 0;
    const listener = () => {
      if (++calls === 1) {
        target.addEventListener("bonk", listener);
        target.dispatchEvent(new Event("bonk"));
      }
    };
    target.addEventListener("bonk", listener, { once: true });
    target.dispatchEvent(new Event("bonk"));
    expect(calls).toBe(2);
    target.dispatchEvent(new Event("bonk"));
    expect(calls).toBe(3);
    expect(target.removeEventListener).not.toHaveBeenCalled();
  });

  it("accepts callable options dictionaries for addition and removal", () => {
    eventTargetHook({}, {});
    const target = new (class extends EventTarget {
      [internal] = makeInternal({ instance: new EventTarget() });
    })();
    const listener = vi.fn();
    const options = Object.assign(() => {}, { capture: false, once: true });
    target.addEventListener("bonk", listener, options);
    target.dispatchEvent(new Event("bonk"));
    target.addEventListener("bonk", listener, options);
    target.dispatchEvent(new Event("bonk"));
    expect(listener).toHaveBeenCalledTimes(2);

    target.addEventListener("bonk", listener, false);
    target.removeEventListener("bonk", listener, options);
    target.dispatchEvent(new Event("bonk"));
    expect(listener).toHaveBeenCalledTimes(2);
  });

  it("snapshots options at registration, before the instance exists", () => {
    eventTargetHook({}, {});
    const target = new (class extends EventTarget {
      [internal] = makeInternal<EventTarget, object>({});
    })();
    const listener = vi.fn();
    const controller = new AbortController();
    const read = {
      capture: vi.fn(() => true),
      once: vi.fn(() => false),
      passive: vi.fn(() => false),
      signal: vi.fn(() => controller.signal),
    };
    const options = Object.defineProperties(
      {},
      Object.fromEntries(Object.entries(read).map(([k, get]) => [k, { get }])),
    );
    target.addEventListener("bonk", listener, options);

    // Mutations after registration must not affect it
    read.capture.mockReturnValue(false);
    read.once.mockReturnValue(true);
    read.signal.mockReturnValue(AbortSignal.abort());
    target[internal].instance = new EventTarget();
    connectEventListeners(target);

    target.dispatchEvent(new Event("bonk"));
    target.dispatchEvent(new Event("bonk"));
    expect(listener).toHaveBeenCalledTimes(2); // neither once nor aborted
    expect(
      target[internal].listeners.get("bonk")?.get(listener)?.capturingArgs,
    ).toBeDefined();
    controller.abort();
    target.dispatchEvent(new Event("bonk"));
    expect(listener).toHaveBeenCalledTimes(2); // original signal honored
    for (const get of Object.values(read)) {
      expect(get).toHaveBeenCalledOnce();
    }
  });
});

describe("hookEventProperty", () => {
  it("sets up a getter to return from the internal object", () => {
    class Target {
      [internal] = makeInternal({ onbonk: "internal" });
      get onbonk() {
        return "original";
      }
    }
    hookEventProperty(Target.prototype, "onbonk");
    const target = new Target();
    expect(target.onbonk).toBe("internal");
  });

  it("sets up a setter to write to the internal object", () => {
    class Target {
      [internal] = makeInternal<Target, { onbonk: unknown }>({
        onbonk: "internal",
      });
      set onbonk(_: unknown) {}
    }
    hookEventProperty(Target.prototype, "onbonk");

    // When no internal instance exists, it just writes to the internal object
    const target = new Target();
    target.onbonk = "written";
    expect(target[internal].onbonk).toBe("written");

    // When an internal instance exists, writes to both the internal object and
    // the instance; to the latter, writes a bound function instead of the
    // original.
    const onbonk = () => {};
    target[internal].instance = new Target();
    target.onbonk = onbonk;
    expect(target[internal].onbonk).toBe(onbonk);
    expect(target[internal].instance.onbonk).toBeInstanceOf(Function);

    // Non-function values are coerced to null on the instance, like native
    target.onbonk = {};
    expect(target[internal].instance.onbonk).toBeNull();
  });

  it("does not interfere with unhooked objects", () => {
    class Target {
      declare [internal]: Internal<Target>;
      #onbonk: unknown;
      get onbonk() {
        return this.#onbonk;
      }
      set onbonk(val: unknown) {
        this.#onbonk = val;
      }
    }
    hookEventProperty(Target.prototype, "onbonk");
    const target = new Target();
    target.onbonk = "hello";
    expect(target[internal]).toBeUndefined();
    expect(target.onbonk).toBe("hello");
  });
});
