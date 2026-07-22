import { CachePartition, OriginStateHolder } from "./originstate";

export type RequestState = {
  fqdn: string;
  isFrame: boolean;
  cachePartition: CachePartition;
  pendingOrigin?: OriginStateHolder;
};

export type Stateful<T> = T & {
  state: RequestState;
};
