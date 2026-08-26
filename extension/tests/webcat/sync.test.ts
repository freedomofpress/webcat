import { inspect } from "node:util";

import { describe, expect, it, vi } from "vitest";

import { Lock, Mutex } from "../../src/webcat/sync";

describe("Mutex", () => {
  it("only allows one caller at a time to acquire", () => {
    const mutex = new Mutex();
    for (let i = 0; i < 5; i++) {
      const promise = mutex.acquire();
      if (i === 0) {
        expect(inspect(promise)).not.toContain("<pending>");
      } else {
        expect(inspect(promise)).toContain("<pending>");
      }
    }
  });

  it("unblocks the next caller on release", async () => {
    const mutex = new Mutex();
    const first = mutex.acquire();
    const second = mutex.acquire();
    const third = mutex.acquire();
    expect(inspect(first)).not.toContain("<pending>");
    expect(inspect(second)).toContain("<pending>");
    expect(inspect(third)).toContain("<pending>");
    mutex.release();
    await second;
    expect(inspect(second)).not.toContain("<pending>");
    expect(inspect(third)).toContain("<pending>");
  });

  it("allows a caller to acquire with an existing lock", async () => {
    const mutex = new Mutex();
    const lock = await mutex.acquire();
    const promise = mutex.acquire(lock);
    expect(inspect(promise)).not.toContain("<pending>");
  });

  it("does not allow a caller to acquire with the wrong lock", () => {
    const mutex = new Mutex();
    mutex.acquire();
    const promise = mutex.acquire(new Lock(mutex));
    expect(inspect(promise)).toContain("<pending>");
  });
});

describe("Lock", () => {
  it("releases its Mutex when disposed", () => {
    const mutex = { release: vi.fn() };
    const lock = new Lock(mutex);
    expect(mutex.release).not.toHaveBeenCalled();
    {
      using _ = lock;
    }
    expect(mutex.release).toHaveBeenCalledOnce();
  });

  it("releases only when all holders have disposed", () => {
    const mutex = { release: vi.fn() };
    const lock = new Lock(mutex);
    function* hold() {
      using _ = lock;
      yield;
    }
    const holders = [];
    for (let i = 0; i < 7; i++) {
      const holder = hold();
      holder.next();
      holders.push(holder);
    }
    expect(mutex.release).not.toHaveBeenCalled();
    while (holders.length > 1) {
      const [holder] = holders.splice(
        Math.floor(Math.random() * holders.length),
        1,
      );
      holder.next();
      expect(mutex.release).not.toHaveBeenCalled();
    }
    holders[0].next();
    expect(mutex.release).toHaveBeenCalledOnce();
  });
});
