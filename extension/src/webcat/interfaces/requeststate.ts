import { CachePartition, OriginState } from "./originstate";

export type RequestState = {
  fqdn: string;
  isFrame: boolean;
  cachePartition: CachePartition;
  pendingOrigin?: OriginState;
  /** A marking filter is attached to the response */
  marked?: boolean;
};

export type Stateful<T> = T & {
  state: RequestState;
};
