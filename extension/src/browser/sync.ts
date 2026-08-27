/**
 * An object that can be held and released by a {@link Lock}.
 */
export type Releasable = { release(): void };

/**
 * A {@link Disposable} that holds a {@link Releasable} (e.g. a {@link Mutex})
 * and releases it when disposed. When multiple scopes hold the same Lock, the
 * Releasable is only released when all holders have disposed.
 */
export class Lock implements Disposable {
  /**
   * The object held by this Lock; usually a {@link Mutex}.
   */
  readonly mutex: Releasable;
  #holders = 0;

  /**
   * @param mutex The object held by this Lock; usually a {@link Mutex}.
   */
  constructor(mutex: Releasable) {
    this.mutex = mutex;
  }

  /**
   * Implements the {@link Disposable} interface.
   */
  get [Symbol.dispose]() {
    this.#holders++;
    return () => {
      this.#holders--;
      if (this.#holders === 0) {
        this.mutex.release();
      }
    };
  }
}

if (!Symbol.dispose) {
  // Workaround for a bug in TypeScript downleveling
  const { get } = Object.getOwnPropertyDescriptor(
    Lock.prototype,
    Symbol.dispose,
  ) as PropertyDescriptor;
  Object.defineProperty(Lock.prototype, Symbol.for("Symbol.dispose"), { get });
  delete Lock.prototype[Symbol.dispose];
}

/**
 * A mutex for enforcing execution order in asynchronous code.
 * 
 * @example
 * class AsyncThing {
 *   #mutex = new Mutex();
 *   async doSomeThings(x) {                    // Guaranteed execution order:
 *     using _ = await this.#mutex.acquire();   //
 *     await thingNumberOne(x);                 // 1.   t.doSomeThings(1)
 *     await thingNumberTwo(x);                 // 1.1. thingNumberOne(1) 
 *   }                                          // 1.2. thingNumberTwo(1)
 * }                                            // 2.   t.doSomethings(2)
 *                                              // 2.1. thingNumberOne(2) 
 * const t = new AsyncThing();                  // 2.2. thingNumberTwo(2)
 * t.doSomeThings(1);                           // 3.   t.doSomethings(3)
 * t.doSomeThings(2);                           // 3.1. thingNumberOne(3) 
 * t.doSomeThings(3);                           // 3.2. thingNumberTwo(3)
 */
export class Mutex implements Releasable {
  #resolvers: [(s: Lock) => void, Lock][] = [];
  #lock?: Lock;

  /**
   * Locks this Mutex. Calling `await mutex.acquire()` on an unlocked Mutex
   * returns immediately. Calling it on a locked Mutex awaits until the Mutex
   * is released. Calling `await mutex.acquire(lock)` with the lock that is
   * holding the Mutex returns immediately and returns the same lock, which is
   * useful, for example, in recursive algorithms.
   * 
   * @param lock An optional Lock that will be used to hold the Mutex.
   * @returns The Lock currently holding the locked Mutex.
   */
  async acquire(lock?: Lock) {
    if (this.#lock === undefined) {
      if (lock && lock.mutex == this) {
        this.#lock = lock;
      } else {
        this.#lock = this.createLock();
      }
      return this.#lock;
    } else if (lock && lock === this.#lock) {
      return this.#lock;
    } else {
      return new Promise<Lock>((resolve) => {
        this.#resolvers.push([resolve, lock ?? this.createLock()]);
      });
    }
  }

  /**
   * Releases this Mutex. Called either directly or by the {@link Lock} holding
   * the Mutex as it gets disposed.
   */
  release() {
    if (this.#resolvers.length > 0) {
      const [next, lock] = this.#resolvers.shift()!; // eslint-disable-line @typescript-eslint/no-non-null-assertion
      this.#lock = lock;
      next?.(this.#lock);
    } else {
      this.#lock = undefined;
    }
  }

  /**
   * @returns A new {@link Lock} for this Mutex. Unlike {@link acquire}, does
   * not lock the Mutex; to use the Lock, pass it to acquire.
   */
  createLock() {
    return new Lock(this);
  }
}
