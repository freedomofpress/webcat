export * from "../webcat/update";

import { WebcatDatabase } from "../webcat/db";

// Override the public functions
export async function initializeScheduledUpdates(
  db: WebcatDatabase,
  // eslint-disable-next-line
  endpoint: string,
): Promise<void> {
  console.log(
    "[TESTING] initializeScheduledUpdates hooked - marking as updated, skipping scheduling",
  );

  // Mark as updated so it won't try to update on navigation
  await db.setLastUpdated();
  await db.setLastChecked();

  return Promise.resolve();
}

export async function retryUpdateIfFailed(): Promise<void> {
  console.log("[TESTING] retryUpdateIfFailed hooked - skipping retry logic");
  return Promise.resolve();
}
