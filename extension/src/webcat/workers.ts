import { KVStore } from "../browser/kvstore";
import { Mutex } from "../browser/sync";

type TabWorkers = {
  /** Top-level commits seen in the tab since the record was created */
  navigation: number;
  /** Worker script URL to the first party of its request, and the count then */
  scripts: Record<string, { firstParty: string; navigation: number }>;
};

/**
 * The first party of every worker script loaded in a tab, recorded at the
 * script's headers stage and replayed for the loads the worker makes.
 *
 * The browser attributes a worker's script request fully, with its frame and
 * ancestors. The loads the worker then makes report frameId 0 on Firefox ESR
 * (https://bugzilla.mozilla.org/show_bug.cgi?id=2048884, fixed in 155) and
 * lack a documentId on all Firefox versions
 * (https://bugzilla.mozilla.org/show_bug.cgi?id=2089453), so resolving them
 * from the tab's frames races the tab's navigation. The registry carries the
 * script request's attribution over to its loads, keyed by the script URL
 * they name as documentUrl, so resolution skips the frames, which may already
 * belong to the next document. Only a prior attribution is stored; a script
 * outlives its document by one top-level navigation. Session storage, like
 * the caches, survives an event page restart. Once a worker's loads carry a
 * documentId, it replaces the URL as the key.
 */
export class WorkerRegistry {
  readonly #store: KVStore;
  readonly #mutex = new Mutex();

  constructor(store: KVStore) {
    this.#store = store;
  }

  async record(tabId: number, url: string, firstParty: string) {
    using _ = await this.#mutex.acquire();
    const tab = await this.#tab(tabId);
    tab.scripts[url] = { firstParty, navigation: tab.navigation };
    await this.#store.set({ [tabId]: tab }, "session");
  }

  /** The first party recorded for a worker script; stale if the tab navigated since */
  async lookup(tabId: number, url: string) {
    const tab = await this.#tab(tabId);
    const script = tab.scripts[url];
    return (
      script && {
        firstParty: script.firstParty,
        stale: script.navigation !== tab.navigation,
      }
    );
  }

  /** Counts a top-level commit and drops the scripts of documents two navigations back */
  async navigated(tabId: number) {
    using _ = await this.#mutex.acquire();
    const tab = await this.#tab(tabId);
    tab.navigation++;
    for (const [url, script] of Object.entries(tab.scripts)) {
      if (script.navigation < tab.navigation - 1) delete tab.scripts[url];
    }
    if (Object.keys(tab.scripts).length) {
      await this.#store.set({ [tabId]: tab }, "session");
    } else {
      await this.#store.remove(String(tabId), "session");
    }
  }

  async forget(tabId: number) {
    await this.#store.remove(String(tabId), "session");
  }

  async #tab(tabId: number): Promise<TabWorkers> {
    return (
      (await this.#store.get(String(tabId), "session")) ?? {
        navigation: 0,
        scripts: {},
      }
    );
  }
}
