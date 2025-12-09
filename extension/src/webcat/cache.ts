type Destructible = { destructor?: () => void };

export class LRUCache<K, V extends Destructible> {
  private cache: Map<K, V>;
  private limit: number;

  constructor(limit: number) {
    this.limit = limit;
    this.cache = new Map<K, V>();
  }

  private callDestructor(value: V): void {
    if (value.destructor) {
      value.destructor();
    }
  }

  get(key: K): V | undefined {
    if (!this.cache.has(key)) return undefined;

    const value = this.cache.get(key) as V;
    this.cache.delete(key);
    this.cache.set(key, value);
    return value;
  }

  set(key: K, value: V): void {
    if (this.cache.has(key)) {
      // Remove the old value to update its position
      this.cache.delete(key);
    } else if (this.cache.size >= this.limit) {
      // Remove the least recently used key (first key in the Map)
      const oldestKey = this.cache.keys().next().value;
      if (oldestKey !== undefined) {
        this.cache.delete(oldestKey);
      }
    }
    this.cache.set(key, value);
  }

  has(key: K): boolean {
    return this.cache.has(key);
  }

  keys(): K[] {
    return Array.from(this.cache.keys());
  }

  delete(key: K): void {
    const value = this.cache.get(key);
    if (value !== undefined) {
      this.callDestructor(value);
    }
    this.cache.delete(key);
  }
}

export class LRUSet<T> {
  private cache: Set<T>;
  private limit: number;

  constructor(limit: number) {
    this.limit = limit;
    this.cache = new Set<T>();
  }

  has(value: T): boolean {
    if (!this.cache.has(value)) return false;
    // Move the accessed value to the end to mark it as recently used
    this.cache.delete(value);
    this.cache.add(value);
    return true;
  }

  add(value: T): void {
    if (this.cache.has(value)) {
      // Remove the old value to update its position
      this.cache.delete(value);
    } else if (this.cache.size >= this.limit) {
      // Remove the least recently used value (first item in the Set)
      const oldestValue = this.cache.values().next().value;
      if (oldestValue !== undefined) {
        this.cache.delete(oldestValue);
      }
    }
    this.cache.add(value);
  }

  values(): T[] {
    return Array.from(this.cache.values());
  }
}
