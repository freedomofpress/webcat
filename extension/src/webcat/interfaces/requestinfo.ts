import { OriginStateHolder } from "./originstate";

export type CachePartition = { firstParty: string; incognito: boolean };

export type RequestInfoParams = {
  pendingOrigin: OriginStateHolder;
  cachePartition: CachePartition;
};

export class RequestInfo {
  pendingOrigin: OriginStateHolder;
  cachePartition: CachePartition;
  completed: Promise<void>;
  #resolve?: () => void;
  #reject?: () => void;

  constructor({ pendingOrigin, cachePartition }: RequestInfoParams) {
    const { promise, resolve, reject } = Promise.withResolvers<void>();
    this.completed = promise;
    this.complete = resolve;
    this.fail = reject;
    this.pendingOrigin = pendingOrigin;
    this.cachePartition = cachePartition;
  }

  complete() {
    this.#resolve?.();
  }

  fail() {
    this.#reject?.();
  }
}
