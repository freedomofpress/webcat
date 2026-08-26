export class Lock implements Disposable {
  readonly mutex: Mutex;
  #users = 0;

  constructor(mutex: Mutex) {
    this.mutex = mutex;
  }

  get [Symbol.dispose]() {
    this.#users++;
    return () => {
      this.#users--;
      if (this.#users === 0) {
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

export class Mutex {
  #resolvers: ((s: Lock) => void)[] = [];
  #lock?: Lock;

  async acquire(lock?: Lock) {
    if (this.#lock === undefined) {
      this.#lock = new Lock(this);
      return this.#lock;
    } else if (lock && lock === this.#lock) {
      return this.#lock;
    } else {
      return new Promise<Lock>((resolve) => {
        this.#resolvers.push(resolve);
      });
    }
  }

  release() {
    if (this.#resolvers.length > 0) {
      this.#lock = new Lock(this);
      const next = this.#resolvers.shift();
      next?.(this.#lock);
    } else {
      this.#lock = undefined;
    }
  }
}
