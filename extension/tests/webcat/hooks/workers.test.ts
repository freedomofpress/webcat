import { afterEach, beforeEach, describe, expect, it, Mock, vi } from "vitest";

import { global } from "../../../src/webcat/hooks/core";
import {
  serviceWorkerHook,
  sharedWorkerHook,
  workerHook,
} from "../../../src/webcat/hooks/workers";

describe("sharedWorkerHook", () => {
  let SharedWorkerStub: Mock<{ new (): void }>;
  let MessagePortStub: Mock<{ new (): void }>;

  beforeEach(() => {
    class MessagePort {
      #onmessage: null | ((event: Event) => void) = null;
      get onmessage() {
        return this.#onmessage;
      }
      #onmessageerror: null | ((event: Event) => void) = null;
      get onmessageerror() {
        return this.#onmessageerror;
      }

      postMessage() {}
      start() {}
      close() {}
    }
    MessagePortStub = vi.fn<{ new (): void }>(MessagePort);
    Object.defineProperties(
      MessagePortStub.prototype,
      Object.getOwnPropertyDescriptors(MessagePort.prototype),
    );
    vi.stubGlobal("MessagePort", MessagePortStub);
    class SharedWorker {
      #port = new MessagePortStub();
      get port() {
        return this.#port;
      }
      #onerror: null | ((event: Event) => void) = null;
      get onerror() {
        return this.#onerror;
      }
    }
    SharedWorkerStub = vi.fn<{ new (): void }>(SharedWorker);
    Object.defineProperties(
      SharedWorkerStub.prototype,
      Object.getOwnPropertyDescriptors(SharedWorker.prototype),
    );
    vi.stubGlobal("SharedWorker", SharedWorkerStub);
  });

  afterEach(() => {
    vi.unstubAllGlobals();
  });

  it("replaces the SharedWorker constructor when present", () => {
    sharedWorkerHook({}, "placeholder");
    expect(SharedWorker).not.toBe(SharedWorkerStub);
  });

  it("does not throw when no SharedWorker constructor is available", () => {
    vi.unstubAllGlobals();
    expect(() => {
      sharedWorkerHook({}, { firstParty: "encrypted-fpo-string" });
    }).not.toThrow();
  });

  it("throws when constructor is called without new", () => {
    sharedWorkerHook({}, "placeholder");
    expect(SharedWorker).toThrow("SharedWorker constructor: 'new' is required");
  });

  it("throws when constructor is called with zero arguments", () => {
    sharedWorkerHook({}, "placeholder");
    expect(() => {
      new (SharedWorker as unknown as new () => void)();
    }).toThrow(
      "SharedWorker constructor: At least 1 argument required, but only 0 passed",
    );
  });

  it("calls the original constructor only after data is available", async () => {
    const scope = {};

    sharedWorkerHook(scope, "placeholder");
    const options = { type: "classic" } as const;
    new SharedWorker("/worker.js", options);
    expect(SharedWorkerStub).not.toHaveBeenCalled();

    sharedWorkerHook(scope, { firstParty: "encrypted-fpo-string" });
    await vi.waitFor(() => {
      expect(SharedWorkerStub).toHaveBeenCalled();
    });
    expect(SharedWorkerStub).toHaveBeenCalledExactlyOnceWith(
      "/worker.js#encrypted-fpo-string",
      options,
    );
  });

  it("directly calls port.postMessage when an instance is available", async () => {
    const scope = {};
    const postMessage = vi.spyOn(MessagePortStub.prototype, "postMessage");

    sharedWorkerHook(scope, "placeholder");
    const options = { type: "classic" } as const;
    const worker = new SharedWorker("/worker.js", options);

    sharedWorkerHook(scope, { firstParty: "encrypted-fpo-string" });
    await vi.waitFor(() => {
      expect(SharedWorkerStub).toHaveBeenCalled();
    });

    worker.port.postMessage("hello");
    expect(postMessage).toHaveBeenCalledExactlyOnceWith("hello");
  });

  it("buffers calls port.postMessage until an instance is available", async () => {
    const scope = {};
    const postMessage = vi.spyOn(MessagePortStub.prototype, "postMessage");

    sharedWorkerHook(scope, "placeholder");
    const options = { type: "classic" } as const;
    const worker = new SharedWorker("/worker.js", options);

    worker.port.postMessage("hello");
    worker.port.postMessage({}, []);
    expect(postMessage).not.toHaveBeenCalled();

    sharedWorkerHook(scope, { firstParty: "encrypted-fpo-string" });
    await vi.waitFor(() => {
      expect(SharedWorkerStub).toHaveBeenCalled();
    });
    expect(postMessage).toHaveBeenCalledTimes(2);
    expect(postMessage).toHaveBeenCalledWith("hello");
    expect(postMessage).toHaveBeenCalledWith({}, []);
  });

  it("directly calls port.start when an instance is available", async () => {
    const scope = {};
    const start = vi.spyOn(MessagePortStub.prototype, "start");

    sharedWorkerHook(scope, "placeholder");
    const options = { type: "classic" } as const;
    const worker = new SharedWorker("/worker.js", options);

    sharedWorkerHook(scope, { firstParty: "encrypted-fpo-string" });
    await vi.waitFor(() => {
      expect(SharedWorkerStub).toHaveBeenCalled();
    });

    worker.port.start();
    expect(start).toHaveBeenCalledExactlyOnceWith();
  });

  it("buffers calls port.start until an instance is available", async () => {
    const scope = {};
    const start = vi.spyOn(MessagePortStub.prototype, "start");

    sharedWorkerHook(scope, "placeholder");
    const options = { type: "classic" } as const;
    const worker = new SharedWorker("/worker.js", options);

    worker.port.start();
    expect(start).not.toHaveBeenCalled();

    sharedWorkerHook(scope, { firstParty: "encrypted-fpo-string" });
    await vi.waitFor(() => {
      expect(SharedWorkerStub).toHaveBeenCalled();
    });
    expect(start).toHaveBeenCalledExactlyOnceWith();
  });

  it("directly calls port.close when an instance is available", async () => {
    const scope = {};
    const close = vi.spyOn(MessagePortStub.prototype, "close");

    sharedWorkerHook(scope, "placeholder");
    const options = { type: "classic" } as const;
    const worker = new SharedWorker("/worker.js", options);

    sharedWorkerHook(scope, { firstParty: "encrypted-fpo-string" });
    await vi.waitFor(() => {
      expect(SharedWorkerStub).toHaveBeenCalled();
    });

    worker.port.close();
    expect(close).toHaveBeenCalledExactlyOnceWith();
  });

  it("buffers calls port.close until an instance is available", async () => {
    const scope = {};
    const close = vi.spyOn(MessagePortStub.prototype, "close");

    sharedWorkerHook(scope, "placeholder");
    const options = { type: "classic" } as const;
    const worker = new SharedWorker("/worker.js", options);

    worker.port.close();
    expect(close).not.toHaveBeenCalled();

    sharedWorkerHook(scope, { firstParty: "encrypted-fpo-string" });
    await vi.waitFor(() => {
      expect(SharedWorkerStub).toHaveBeenCalled();
    });
    expect(close).toHaveBeenCalledExactlyOnceWith();
  });
});

describe("serviceWorkerHook", () => {
  beforeEach(() => {
    vi.stubGlobal("Navigator", {
      prototype: {
        serviceWorker: {},
      },
    });
    vi.stubGlobal("ServiceWorker", class {});
    vi.stubGlobal("ServiceWorkerContainer", class {});
    vi.stubGlobal("ServiceWorkerRegistration", class {});
    vi.stubGlobal("origin", "https://example.com");
  });

  afterEach(() => {
    vi.unstubAllGlobals();
  });

  it("allows ServiceWorkers when top is same-origin", () => {
    vi.stubGlobal("top", {
      origin: "https://example.com",
    });
    serviceWorkerHook({}, "placeholder");
    expect(global.Navigator.prototype.serviceWorker).not.toBeUndefined();
    expect(global.ServiceWorker).not.toBeUndefined();
    expect(global.ServiceWorkerContainer).not.toBeUndefined();
    expect(global.ServiceWorkerRegistration).not.toBeUndefined();
  });

  it("disables ServiceWorkers when top is cross-origin", () => {
    vi.stubGlobal("top", {
      origin: "null",
    });
    serviceWorkerHook({}, "placeholder");
    expect(global.Navigator.prototype.serviceWorker).toBeUndefined();
    expect(global.ServiceWorker).toBeUndefined();
    expect(global.ServiceWorkerContainer).toBeUndefined();
    expect(global.ServiceWorkerRegistration).toBeUndefined();
  });

  it("allows ServiceWorkers when data indicates same-origin", () => {
    serviceWorkerHook({}, { sameOriginWithFirstParty: true });
    expect(global.Navigator.prototype.serviceWorker).not.toBeUndefined();
    expect(global.ServiceWorker).not.toBeUndefined();
    expect(global.ServiceWorkerContainer).not.toBeUndefined();
    expect(global.ServiceWorkerRegistration).not.toBeUndefined();
  });

  it("disables ServiceWorkers when data indicates cross-origin", () => {
    serviceWorkerHook({}, { sameOriginWithFirstParty: false });
    expect(global.Navigator.prototype.serviceWorker).toBeUndefined();
    expect(global.ServiceWorker).toBeUndefined();
    expect(global.ServiceWorkerContainer).toBeUndefined();
    expect(global.ServiceWorkerRegistration).toBeUndefined();
  });
});

describe("workerHook", () => {
  let WorkerStub: Mock<{ new (): void }>;

  beforeEach(() => {
    class Worker {
      #onmessage: null | ((event: Event) => void) = null;
      get onmessage() {
        return this.#onmessage;
      }
      #onerror: null | ((event: Event) => void) = null;
      get onerror() {
        return this.#onerror;
      }
      #onmessageerror: null | ((event: Event) => void) = null;
      get onmessageerror() {
        return this.#onmessageerror;
      }

      postMessage() {}
      terminate() {}
    }
    WorkerStub = vi.fn<{ new (): void }>(Worker);
    Object.defineProperties(
      WorkerStub.prototype,
      Object.getOwnPropertyDescriptors(Worker.prototype),
    );
    vi.stubGlobal("Worker", WorkerStub);
  });

  afterEach(() => {
    vi.unstubAllGlobals();
  });

  it("replaces the Worker constructor when present", () => {
    workerHook({}, "placeholder");
    expect(Worker).not.toBe(WorkerStub);
  });

  it("does not throw when no Worker constructor is available", () => {
    vi.unstubAllGlobals();
    expect(() => {
      workerHook({}, { firstParty: "encrypted-fpo-string" });
    }).not.toThrow();
  });

  it("throws when constructor is called without new", () => {
    workerHook({}, "placeholder");
    expect(Worker).toThrow("Worker constructor: 'new' is required");
  });

  it("throws when constructor is called with zero arguments", () => {
    workerHook({}, "placeholder");
    expect(() => {
      new (Worker as unknown as new () => void)();
    }).toThrow(
      "Worker constructor: At least 1 argument required, but only 0 passed",
    );
  });

  it("calls the original constructor only after data is available", async () => {
    const scope = {};

    workerHook(scope, "placeholder");
    const options = { type: "classic" } as const;
    new Worker("/worker.js", options);
    expect(WorkerStub).not.toHaveBeenCalled();

    workerHook(scope, { firstParty: "encrypted-fpo-string" });
    await vi.waitFor(() => {
      expect(WorkerStub).toHaveBeenCalled();
    });
    expect(WorkerStub).toHaveBeenCalledExactlyOnceWith(
      "/worker.js#encrypted-fpo-string",
      options,
    );
  });

  it("directly calls postMessage when an instance is available", async () => {
    const scope = {};
    const postMessage = vi.spyOn(WorkerStub.prototype, "postMessage");

    workerHook(scope, "placeholder");
    const options = { type: "classic" } as const;
    const worker = new Worker("/worker.js", options);

    workerHook(scope, { firstParty: "encrypted-fpo-string" });
    await vi.waitFor(() => {
      expect(WorkerStub).toHaveBeenCalled();
    });

    worker.postMessage("hello");
    expect(postMessage).toHaveBeenCalledExactlyOnceWith("hello");
  });

  it("buffers calls to postMessage until an instance is available", async () => {
    const scope = {};
    const postMessage = vi.spyOn(WorkerStub.prototype, "postMessage");

    workerHook(scope, "placeholder");
    const options = { type: "classic" } as const;
    const worker = new Worker("/worker.js", options);

    worker.postMessage("hello");
    worker.postMessage({}, []);
    expect(postMessage).not.toHaveBeenCalled();

    workerHook(scope, { firstParty: "encrypted-fpo-string" });
    await vi.waitFor(() => {
      expect(WorkerStub).toHaveBeenCalled();
    });
    expect(postMessage).toHaveBeenCalledTimes(2);
    expect(postMessage).toHaveBeenCalledWith("hello");
    expect(postMessage).toHaveBeenCalledWith({}, []);
  });

  it("directly calls terminate when an instance is available", async () => {
    const scope = {};
    const terminate = vi.spyOn(WorkerStub.prototype, "terminate");

    workerHook(scope, "placeholder");
    const options = { type: "classic" } as const;
    const worker = new Worker("/worker.js", options);

    workerHook(scope, { firstParty: "encrypted-fpo-string" });
    await vi.waitFor(() => {
      expect(WorkerStub).toHaveBeenCalled();
    });

    worker.terminate();
    expect(terminate).toHaveBeenCalledExactlyOnceWith();
  });

  it("buffers calls to terminate until an instance is available", async () => {
    const scope = {};
    const terminate = vi.spyOn(WorkerStub.prototype, "terminate");

    workerHook(scope, "placeholder");
    const options = { type: "classic" } as const;
    const worker = new Worker("/worker.js", options);

    worker.terminate();
    expect(terminate).not.toHaveBeenCalled();

    workerHook(scope, { firstParty: "encrypted-fpo-string" });
    await vi.waitFor(() => {
      expect(WorkerStub).toHaveBeenCalled();
    });
    expect(terminate).toHaveBeenCalledExactlyOnceWith();
  });
});
