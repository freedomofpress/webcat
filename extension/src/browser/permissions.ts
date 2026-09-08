export interface Subject {
  name: string;
}

export class PermissionErrorEvent extends Event {
  readonly subject: Subject;
  readonly permission: string;

  constructor(subject: Subject, permission: string) {
    super("permissionerror", { cancelable: true });
    this.subject = subject;
    this.permission = permission;
  }
}

export class PermissionRestoredEvent extends Event {
  readonly subject: Subject;
  readonly permission: string;

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

// eslint-disable-next-line @typescript-eslint/no-unsafe-declaration-merging
export class PermissionChecker extends EventTarget {
  #requirements = new Map<Subject, Set<string>>();
  #missing = new Map<Subject, Set<string>>();

  constructor() {
    super();
    browser.permissions.onAdded.addListener(this.#handleAdded.bind(this));
    browser.permissions.onRemoved.addListener(this.#handleRemoved.bind(this));
  }

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

  getRequired(subject: Subject): Set<string> {
    return new Set(this.#requirements.get(subject));
  }

  getMissing(subject: Subject): Set<string> {
    return new Set(this.#missing.get(subject));
  }

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

export default new PermissionChecker();
