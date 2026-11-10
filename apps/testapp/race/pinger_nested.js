(async () => {
  for (;;) {
    const w = new Worker("/race/ping.js?" + Math.random());
    setTimeout(() => w.terminate(), 500);
    await new Promise((r) => setTimeout(r, 5));
  }
})();
