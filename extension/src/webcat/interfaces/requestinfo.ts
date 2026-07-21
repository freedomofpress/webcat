import { OriginStateHolder } from "./originstate";

export type CachePartition = { firstParty: string; incognito: boolean };

export type RequestInfoParams = {
  pendingOrigin: OriginStateHolder;
  cachePartition: CachePartition;
};

export class RequestInfo {
  pendingOrigin: OriginStateHolder;
  cachePartition: CachePartition;

  constructor({ pendingOrigin, cachePartition }: RequestInfoParams) {
    this.pendingOrigin = pendingOrigin;
    this.cachePartition = cachePartition;
  }
}
