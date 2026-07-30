import { CachePartition, OriginState } from "./originstate";

export type RequestState = {
  fqdn: string;
  isFrame: boolean;
  cachePartition: CachePartition;
  pendingOrigin?: OriginState;
};

export type Stateful<T> = T & {
  state: RequestState;
};
