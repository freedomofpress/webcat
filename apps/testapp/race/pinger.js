// Fetches as fast as it can, so some requests are still in flight when the
// page navigates away
(async () => {
  for (;;) {
    try {
      await fetch("/race/ping.js?" + Math.random(), { cache: "no-store" });
    } catch (e) {}
  }
})();
