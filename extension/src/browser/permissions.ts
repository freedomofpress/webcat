/**
 * The subject of a permission check. Typically a class or a method, but may
 * also be a function or any object with a name property.
 */
export interface Subject {
  /** The name of the subject. */
  name: string;
}

/**
 * The `permissionerror` event. Notifies the consumer of a missing permission.
 */
export class PermissionErrorEvent extends Event {
  /**
   * The subject of the missing permission passed to the decorator returned by
   * {@link PermissionChecker.require}.
   */
  readonly subject: Subject;
  /**
   * The missing permission, as declared via {@link PermissionChecker.require}.
   */
  readonly permission: string;

  /** @internal */
  constructor(subject: Subject, permission: string) {
    super("permissionerror", { cancelable: true });
    this.subject = subject;
    this.permission = permission;
  }
}

/**
 * The `permissionrestored` event. Notifies the consumer of a required
 * permission gained by a subject.
 */
export class PermissionRestoredEvent extends Event {
  /** The subject that required the permission. */
  readonly subject: Subject;
  /**
   * The required permission, as declared via
   * {@link PermissionChecker.require}.
   */
  readonly permission: string;

  /** @internal */
  constructor(subject: Subject, permission: string) {
    super("permissionrestored", { cancelable: true });
    this.subject = subject;
    this.permission = permission;
  }
}

// eslint-disable-next-line @typescript-eslint/no-unsafe-declaration-merging
export interface PermissionChecker {
  /** @group Methods */
  addEventListener: EventTarget["addEventListener"] &
    ((
      type: "permissionerror",
      callback: (event: PermissionErrorEvent) => void,
    ) => void) &
    ((
      type: "permissionrestored",
      callback: (event: PermissionRestoredEvent) => void,
    ) => void);
}

/**
 * Checks extension permissions and triggers warnings for missing ones. For
 * an example, {@link PermissionChecker.require}.
 */
// eslint-disable-next-line @typescript-eslint/no-unsafe-declaration-merging
export class PermissionChecker extends EventTarget {
  #requirements = new Map<Subject, Set<string>>();
  #missing = new Map<Subject, Set<string>>();

  constructor() {
    super();
    browser.permissions.onAdded.addListener(this.#handleAdded.bind(this));
    browser.permissions.onRemoved.addListener(this.#handleRemoved.bind(this));
  }

  /**
   * Creates a decorator that checks for an extension permission. For a class
   * or method that requires multiple permissions, use multiple decorators.
   *
   * Permissions are checked at declaration time, not at instantiation or call
   * time. Permission checks are asynchronous, best-effort, and do not block
   * any code from running.
   *
   * Permission warnings in the console may be suppressed by calling
   * {@link PermissionErrorEvent.preventDefault}.
   *
   * @param permission The extension permission to require. May be either a
   *   {@link https://developer.mozilla.org/en-US/docs/Mozilla/Add-ons/WebExtensions/manifest.json/permissions#api_permissions | named permission}
   *   or a {@link https://developer.mozilla.org/en-US/docs/Mozilla/Add-ons/WebExtensions/Match_patterns | match pattern}
   *   for a {@link https://developer.mozilla.org/en-US/docs/Mozilla/Add-ons/WebExtensions/manifest.json/host_permissions | host permission}.
   * @returns
   *
   * @example
   * import permissions from "@freedomofpress/webcat/browser/permissions";
   *
   * @permissions.require("webRequest")
   * @permissions.require("webRequestBlocking")
   * @permissions.require("https://example.com/*")
   * class ExampleBlocker {
   *   ...
   * }
   */
  require(permission: string) {
    return (subject: Subject) => {
      let requirements = this.#requirements.get(subject);
      if (!requirements) {
        requirements = new Set<string>();
        this.#requirements.set(subject, requirements);
      }
      requirements.add(permission);
      this.#checkOne(subject, permission);
    };
  }

  /**
   * Reads the required permissions for a subject. If subject is omitted,
   * reads the required permissions across all subjects.
   *
   * @param subject The subject of the permissions.
   * @returns The set of permissions declared for the subject via
   *   {@link require}, or if no subject is given, permissions across all
   *   subjects.
   */
  getRequired(subject?: Subject): Set<string> {
    if (subject) {
      return new Set(this.#requirements.get(subject));
    }
    return this.#requirements.values().reduce((all, permissions) => {
      return all.union(permissions);
    }, new Set<string>());
  }

  /**
   * Reads the missing permissions for a subject. If subject is omitted, reads
   * the missing permissions across all subjects.
   *
   * @param subject The subject of the permissions.
   * @returns The set of missing permissions required by the subject via
   *   {@link require}, or if no subject is given, missing permissions across
   *   all subjects.
   */
  getMissing(subject?: Subject): Set<string> {
    if (subject) {
      return new Set(this.#missing.get(subject));
    }
    return this.#missing.values().reduce((all, missing) => {
      return all.union(missing);
    }, new Set<string>());
  }

  /**
   * Checks the permissions of a given subject.
   *
   * @param subject The subject of the permissions.
   * @returns A Promise that resolves to true if the subject has all the
   *   permissions required.
   */
  async check(subject: Subject): Promise<boolean> {
    const requirements = this.#requirements.get(subject) ?? new Set();
    const checks = Array.from(requirements).map((r) =>
      this.#checkOne(subject, r),
    );
    const results = await Promise.all<boolean>(checks);
    return results.every((ok) => ok);
  }

  async #checkOne(subject: Subject, permission: string): Promise<boolean> {
    // Is it a host permission or named permission?
    const permissions = new Array<string>();
    const origins = new Array<string>();
    if (permission.includes("://") || permission === "<all_urls>") {
      origins.push(permission);
    } else {
      permissions.push(permission);
    }
    // Run the check
    return browser.permissions.contains({ permissions, origins }).then((ok) => {
      if (ok) {
        const missing = this.#missing.get(subject);
        if (missing) {
          if (missing.delete(permission)) {
            const event = new PermissionRestoredEvent(subject, permission);
            this.dispatchEvent(event);
          }
        }
      } else {
        let missing = this.#missing.get(subject);
        if (!missing) {
          missing = new Set();
          this.#missing.set(subject, missing);
        }
        if (!missing.has(permission)) {
          missing.add(permission);
          const event = new PermissionErrorEvent(subject, permission);
          this.dispatchEvent(event);
          if (!event.defaultPrevented) {
            console.warn(
              "Extension permission requirements not fulfilled for %s. " +
                "The '%s' permission is required.",
              subject.name,
              permission,
            );
          }
        }
      }
      return ok;
    });
  }

  #handleAdded() {
    for (const [subject, set] of this.#missing) {
      if (set.size > 0) {
        this.check(subject);
      }
    }
  }

  #handleRemoved() {
    for (const [subject, _] of this.#requirements) {
      this.check(subject);
    }
  }
}

/**
 * The default {@link PermissionChecker} instance. For an example, see
 * {@link PermissionChecker.require}.
 */
export default new PermissionChecker();
