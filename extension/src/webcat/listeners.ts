export async function installListener() {
  console.log("[webcat] Running installListener");
  // Startupinstall logic is in globals.ts on the main thread
  // TBB/incognito window only mode don't seem to call these listeners
}

export async function startupListener() {
  console.log("[webcat] Running startupListener");
  // Startupinstall logic is in globals.ts on the main thread
  // TBB/incognito window only mode don't seem to call these listeners
}
