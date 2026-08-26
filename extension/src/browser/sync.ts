export type Releasable = { release(): void };

export class Lock implements Disposable {
  readonly mutex: Releasable;
  #holders = 0;

  constructor(mutex: Releasable) {
    this.mutex = mutex;
  }

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

export class Mutex implements Releasable {
  #resolvers: [(s: Lock) => void, Lock][] = [];
  #lock?: Lock;

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

  release() {
    if (this.#resolvers.length > 0) {
      const [next, lock] = this.#resolvers.shift()!; // eslint-disable-line @typescript-eslint/no-non-null-assertion
      this.#lock = lock;
      next?.(this.#lock);
    } else {
      this.#lock = undefined;
    }
  }

  createLock() {
    return new Lock(this);
  }
}
