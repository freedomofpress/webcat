import validator_set from "./validator_set";
import { WebcatDatabaseConfig } from "./webcat/db";
import { BundleFetcherConfig } from "./webcat/originstate";
import { EnrollmentUpdaterOptions } from "./webcat/updater";

export type WebcatConfig = BundleFetcherConfig &
  WebcatDatabaseConfig &
  Omit<EnrollmentUpdaterOptions, "database"> & {
    iconsPath: string;
    pagesPath: string;
  };

const defaultConfig: WebcatConfig = {
  namespace: "WEBCAT",
  originCacheSize: 32,
  nonOriginCacheSize: 8192,

  bundlePath: "/.well-known/webcat/bundle.json",
  bundlePrevPath: "/.well-known/webcat/bundle-prev.json",

  endpoint: "https://webcat.freedom.press/",
  localDataPath: "data",
  validatorSet: validator_set,
  // During alpha, update every hour. Wall-clock based so that sleep/suspend
  // doesn't silently postpone updates.
  updateInterval: 60 * 60 * 1000, // 1 hour
  checkInterval: 5 * 60 * 1000, // poll every 5 minutes
  fetchTimeout: 3000, // 3 second timeout for fetches

  iconsPath: "icons",
  pagesPath: "pages",
};

const testConfig: WebcatConfig = Object.assign(structuredClone(defaultConfig), {
  originCacheSize: 2,
  endpoint: "http://localhost:1234/",
});

export default {
  default: defaultConfig,
  test: testConfig,
};
