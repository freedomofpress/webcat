// Minimal consumer of the webcat npm package: all bundled assets live under
// webcat/ instead of the extension's default root-level paths
import webcat from "webcat";

webcat.start({
  endpoint: "http://localhost:1234/",
  localDataPath: "webcat/data",
  staticHookPath: "webcat/hooks/content.js",
  iconPaths: (p) => `webcat/icons/${p.colorScheme}/${p.name}.SVG`,
  pagePaths: (p) => `webcat/pages/${p.name}.html`,
});
