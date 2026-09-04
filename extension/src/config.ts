import validator_set from "./validator_set";
import { WebcatDatabaseConfig } from "./webcat/db";
import { BundleFetcherConfig } from "./webcat/originstate";
import { EnrollmentUpdaterOptions } from "./webcat/updater";

/**
 * Global WEBCAT configuration. See {@link defaults}.
 *
 * @interface
 */
export type WebcatConfig = BundleFetcherConfig &
  WebcatDatabaseConfig &
  Omit<EnrollmentUpdaterOptions, "database"> & {
    /**
     * The path to the static hook content script file, relative to the
     * extension root directory.
     */
    staticHookPath: string;
    /**
     * The path to the icons directory. The expected directory structure
     * is as follows:
     *
     * ```
     * iconsPath/
     * ├── dark
     * │   ├── webcat-error.SVG
     * │   ├── webcat-ok.SVG
     * │   └── webcat.SVG
     * └── light
     *     ├── webcat-error.SVG
     *     ├── webcat-ok.SVG
     *     └── webcat.SVG
     * ```
     */
    iconsPath: string;
    /**
     * The path to the pages directory containing the extension's standalone
     * HTML pages and their assets.
     */
    pagesPath: string;
  };

/** Default {@link WebcatConfig} values. */
export const defaults = {
  /** {@inheritDoc WebcatConfig.namespace} */
  namespace: "WEBCAT",
  /** {@inheritDoc WebcatConfig.originCacheSize} */
  originCacheSize: 32,
  /** {@inheritDoc WebcatConfig.nonOriginCacheSize} */
  nonOriginCacheSize: 8192,

  /** {@inheritDoc WebcatConfig.bundlePath} */
  bundlePath: "/.well-known/webcat/bundle.json",
  /** {@inheritDoc WebcatConfig.bundlePrevPath} */
  bundlePrevPath: "/.well-known/webcat/bundle-prev.json",

  /** {@inheritDoc WebcatConfig.endpoint} */
  endpoint: "https://webcat.freedom.press/",
  /** {@inheritDoc WebcatConfig.localDataPath} */
  localDataPath: "data",
  /** {@inheritDoc WebcatConfig.validatorSet} */
  validatorSet: validator_set,
  // During alpha, update every hour. Wall-clock based so that sleep/suspend
  // doesn't silently postpone updates.
  /** {@inheritDoc WebcatConfig.updateInterval} */
  updateInterval: 60 * 60 * 1000, // 1 hour
  /** {@inheritDoc WebcatConfig.checkInterval} */
  checkInterval: 5 * 60 * 1000, // poll every 5 minutes
  /** {@inheritDoc WebcatConfig.fetchTimeout} */
  fetchTimeout: 3000, // 3 second timeout for fetches

  /** {@inheritDoc WebcatConfig.staticHookPath} */
  staticHookPath: "dist/hooks/content.js",
  /** {@inheritDoc WebcatConfig.iconsPath} */
  iconsPath: "icons",
  /** {@inheritDoc WebcatConfig.pagesPath} */
  pagesPath: "pages",
} as const satisfies WebcatConfig;

/** @internal */
export const test: WebcatConfig = Object.assign(structuredClone(defaults), {
  originCacheSize: 2,
  endpoint: "http://localhost:1234/",
});
