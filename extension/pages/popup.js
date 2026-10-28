const i18n = (key, ...subs) => browser.i18n.getMessage("WEBCAT_" + key, subs);

const renderers = {
  permissions: {
    message(missing) {
      return i18n("missingPermissions", Array.from(missing).join("\n"));
    },
    button(missing) {
      const b = document.createElement("button");
      b.textContent = i18n("fix");
      b.addEventListener("click", () => {
        const [permissions, origins] = [[], []];
        for (const permission of missing) {
          if (permission.includes("://") || permission === "<all_urls>") {
            origins.push(permission);
          } else {
            permissions.push(permission);
          }
        }
        try {
          browser.permissions.request({ permissions, origins });
          window.close();
        } catch {
          // TODO: browser.permissions.request may throw. Fall back to opening
          // a documentation page with guidance on resolving the issue manually
        }
      });
      return b;
    },
  },
};

function el(tag, text, attrs = {}) {
  const e = document.createElement(tag);
  if (text !== undefined) e.textContent = text;
  for (const [k, v] of Object.entries(attrs)) e.setAttribute(k, v);
  return e;
}

// Renders an http(s) URL as a link and anything else as plain text
function link(href, text = href) {
  if (!/^https?:$/.test(URL.parse(href)?.protocol)) {
    return el("span", text);
  }
  return el("a", text, { href, target: "_blank", rel: "noreferrer" });
}

const EXPLORER = "https://explore.webcat.tech/";
// Served by the background; see WebcatUI.JSON_ORIGIN
const JSON_ORIGIN = "https://json.webcat.invalid";

// Origins are stored under "<namespace>:origins:<key>"; the suffix finds the
// entry without knowing the namespace.
async function loadStored(entry) {
  const all = await browser.storage.session.get(null);
  const suffix = ":origins:" + entry.key;
  return Object.entries(all).find(([k]) => k.endsWith(suffix))?.[1];
}

// Sigsum enrollments key logs by public key; proofs name them by key hash
async function sigsumLogsByKeyHash(logs) {
  const byHash = {};
  for (const [pubkey, url] of Object.entries(logs)) {
    const raw = Uint8Array.fromBase64(pubkey, { alphabet: "base64url" });
    const hash = new Uint8Array(await crypto.subtle.digest("SHA-256", raw));
    byHash[hash.toHex()] = url;
  }
  return byHash;
}

const proofLine = (proof, key) =>
  proof.match(new RegExp(`^${key}=(\\S+)`, "m"))?.[1];

// Fulcio certificate extensions (OID prefix 1.3.6.1.4.1.57264.1.)
const FULCIO = "1.3.6.1.4.1.57264.1.";
const SAN = "2.5.29.17";

// Issuer hosts Fulcio accepts, by brand. Unknown issuers show their host.
const PLATFORMS = [
  ["token.actions.githubusercontent.com", "GitHub Actions"],
  ["gitlab", "GitLab CI"],
  ["agent.buildkite.com", "Buildkite"],
  ["oidc.circleci.com", "CircleCI"],
  ["oidc.codefresh.io", "Codefresh"],
  ["buddyusercontent.com", "Buddy"],
  ["accounts.google.com", "Google"],
  ["login.microsoftonline.com", "Microsoft"],
  ["github.com", "GitHub"],
  ["oauth2.sigstore.dev", "Sigstore"],
  ["sigstore.verify.ibm.com", "IBM"],
  ["auth.eclipse.org", "Eclipse Foundation"],
  ["issuer.hello.coop", "Hellō"],
  ["kaggle.com", "Kaggle"],
];
// SHA-256 of the public Sigstore Fulcio root certificates (2021 and 2022
// roots, from sigstore/root-signing trusted_root.json). Issuer and claims are
// shown as facts only when every CA the enrollment pins is one of these.
const PUBLIC_SIGSTORE_ROOTS = [
  "03a38ffb1f450100c2596d1d10b900ac4d504058006dda58199576bbeb9c73d0",
  "3ba7b6cc4e95469d4d334b49cb257ad8537076fa84b0ca87ff4ecfe6a54680c1",
];

// Log ids (SHA-256 of the key) of the public Rekor logs, from the same file
const PUBLIC_REKOR_LOG_IDS = [
  "wNI9atQGlz+VWfO6LRygH4QUfY/8W4RFwiT5i5WRgB0=",
  "zxGZFVvd0FEmjR8WrFwMdcAJ9vtaY/QXf44Y1wUeP6A=",
];

async function isPublicSigstore(trustedRoot) {
  const cas = trustedRoot?.certificateAuthorities ?? [];
  for (const ca of cas) {
    const root = ca.certChain?.certificates?.at(-1)?.rawBytes;
    if (!root) return false;
    const hash = new Uint8Array(
      await crypto.subtle.digest("SHA-256", Uint8Array.fromBase64(root)),
    );
    if (!PUBLIC_SIGSTORE_ROOTS.includes(hash.toHex())) return false;
  }
  return cas.length > 0;
}

const platformName = (host) =>
  PLATFORMS.find(([needle]) => host?.includes(needle))?.[1] ?? host;

// Derives organization/repository, ref and workflow from the Sigstore claims
// of a CI job on a forge (Fulcio's ci-provider issuers: GitHub, GitLab,
// Codefresh, Buildkite, CircleCI, Buddy). Other identities (email, username,
// SPIFFE, Kubernetes, URI) and the value after a "^" prefix pin are shown as is.
function builtFrom(claims) {
  const get = (oid) => claims[oid]?.replace(/^\^/, "");
  const [san = "", sanRef] = (get(SAN) ?? "").split("@");
  const url = URL.parse(san);
  // Kubernetes service account URIs live under kubernetes.io and are identities
  const forge =
    url && /^https?:$/.test(url.protocol) && url.hostname !== "kubernetes.io"
      ? url
      : null;
  const path = forge?.pathname.slice(1) ?? "";
  // GitLab separates project and config path with "//"; the others put the
  // organization and repository in the first two segments
  const [sanRepo, sanConfig] = path.includes("//")
    ? path.split("//")
    : [
        path.split("/").slice(0, 2).join("/"),
        path.split("/").slice(2).join("/"),
      ];
  const repo =
    get(FULCIO + "12") ??
    (forge && sanRepo ? `${forge.origin}/${sanRepo}` : undefined);
  const ref = get(FULCIO + "14") ?? sanRef;
  const config = get(FULCIO + "18")?.split("@")[0] ?? sanConfig;
  const issuer = get(FULCIO + "8") ?? get(FULCIO + "1");
  return {
    repo,
    ref: ref?.replace(/^refs\//, ""),
    workflow: config?.replace(`${repo}/`, "") || undefined,
    identity: get(SAN),
    platform: platformName(URL.parse(issuer ?? "")?.hostname ?? issuer),
  };
}

// Returns [rows, links]: rows for the visible list, log links for Advanced.
async function proofRows(stored) {
  const { enrollment, signatures, provenance } = stored;
  const rows = [];
  const links = [];
  if (enrollment.type === "sigstore") {
    // The log entry is the verified bundle's, recorded at verification time.
    // Its log must be a public Rekor as well, since a private log can carry
    // any logging time.
    const entry = provenance?.logIndex
      ? { logIndex: provenance.logIndex, logId: { keyId: provenance.logId } }
      : undefined;
    const logId = entry?.logId.keyId;
    const publicLog = PUBLIC_REKOR_LOG_IDS.includes(logId);
    const log = enrollment.trusted_root?.tlogs?.find(
      (t) => t.logId?.keyId === logId,
    );
    if (entry && (publicLog || log)) {
      const href = publicLog
        ? `https://search.sigstore.dev/?logIndex=${entry.logIndex}`
        : `${log.baseUrl}/api/v1/log/entries?logIndex=${entry.logIndex}`;
      links.push(link(href, `${i18n("logEntry")} #${entry.logIndex}`));
    }
    if (publicLog && (await isPublicSigstore(enrollment.trusted_root))) {
      rows.push([i18n("signedWith"), el("span", "Sigstore")]);
      // Certificate values beat the pinned claims: they are what was signed
      const facts = { ...enrollment.claims, ...provenance };
      const { repo, ref, workflow, identity, platform } = builtFrom(facts);
      if (platform) rows.push([i18n("platform"), el("span", platform)]);
      if (repo) {
        const repoUrl = URL.parse(repo);
        // The row is text; the repository link goes under Advanced
        rows.push([
          i18n("builtFrom"),
          el("span", repoUrl ? repoUrl.pathname.slice(1) : repo),
        ]);
        links.push(link(repo, i18n("repository")));
        if (ref) rows.push([i18n("ref"), el("span", ref)]);
        if (workflow) rows.push([i18n("workflow"), el("span", workflow)]);
      } else if (identity) {
        rows.push([i18n("signedBy"), el("span", identity)]);
      }
      const run = provenance?.[FULCIO + "21"];
      if (run) {
        links.push(link(run, i18n("ciRun")));
      }
      const commit = provenance?.[FULCIO + "13"];
      if (commit) {
        const short = `${i18n("commit")} ${commit.slice(0, 12)}`;
        links.push(
          repo ? link(`${repo}/commit/${commit}`, short) : el("span", short),
        );
      }
    } else {
      // A private instance is shown like Sigsum: the CA pinned by this site's
      // enrollment is the bound fact
      const ca = enrollment.trusted_root?.certificateAuthorities?.[0]?.uri;
      rows.push([i18n("signedWith"), el("span", i18n("privateSigstore"))]);
      rows.push([
        i18n("signedBy"),
        el("span", i18n("pinnedCA", URL.parse(ca ?? "")?.hostname ?? "CA")),
      ]);
    }
  } else if (enrollment.type === "sigsum") {
    rows.push([i18n("signedWith"), el("span", "Sigsum")]);
    const registered = String(enrollment.signers.length);
    const required = String(enrollment.threshold);
    rows.push([
      i18n("signedBy"),
      el(
        "span",
        provenance?.signed
          ? i18n("signersCount", provenance.signed, registered, required)
          : i18n("signersThreshold", required, registered),
      ),
    ]);
    const logs = await sigsumLogsByKeyHash(enrollment.logs);
    for (const proof of Object.values(signatures ?? {})) {
      const url = logs[proofLine(proof, "log")];
      const index = proofLine(proof, "leaf_index");
      if (url && index) {
        links.push(
          link(
            `${url}/get-leaves/${index}/${index}`,
            `${i18n("logEntry")} ${new URL(url).hostname} #${index}`,
          ),
        );
      }
    }
  }
  return [rows, links];
}

// Renders one origin as a key/value list: the given leading rows, then the
// version and the proof rows, with the links under Advanced.
function keyValueList(rows) {
  const dl = el("dl");
  for (const [label, value] of rows) {
    const text = typeof value === "string" ? value : value.textContent;
    const dd = el("dd", undefined, { title: text ?? "" });
    dd.append(value);
    dl.append(el("dt", label), dd);
  }
  return dl;
}

const when = (seconds) =>
  new Date(seconds * 1000).toLocaleString(undefined, {
    dateStyle: "medium",
    timeStyle: "short",
  });

const version = (stored) => stored.manifest.version.replace(/^\D+(?=\d)/, "");

const icon = (ok) =>
  el("img", undefined, {
    src: ok ? "../icons/webcat-ok.SVG" : "../icons/webcat-error.SVG",
    alt: ok ? "✓" : "✗",
  });

// One row per embedded origin: host, tick or cross, version
function embeddedRow(fqdn, stored, ok = true) {
  const value = el("span", fqdn);
  value.append(" ", icon(ok));
  if (stored) value.append(" ", version(stored));
  return [i18n("embedded"), value];
}

async function renderOrigin(entry, stored, rows, after = []) {
  const section = el("section");
  const links = [];
  if (!stored) {
    rows.push([i18n("details"), i18n("unavailable")]);
  } else {
    rows.push([i18n("version"), version(stored)]);
    if (stored.enrollment) {
      const [proof, logLinks] = await proofRows(stored);
      rows.push(...proof);
      links.push(...logLinks);
      // Both systems set the expiry to the signing time plus max_age: the
      // certificate's issue time for Sigstore, the median witness time for Sigsum
      const signedOn = stored.validUntil - stored.enrollment.max_age;
      const witnesses = stored.provenance?.witnesses;
      rows.push(
        [
          i18n("signedOn"),
          witnesses
            ? i18n("witnessedBy", when(signedOn), witnesses)
            : when(signedOn),
        ],
        [i18n("validUntil"), when(stored.validUntil)],
      );
    }
  }
  rows.push(...after);
  section.append(keyValueList(rows));
  if (!stored) {
    return section;
  }
  const details = el("details");
  const linkList = el("div", undefined, { class: "links" });
  linkList.append(...links);
  // A tab created through the tabs API runs in a web process, where
  // Firefox's JSON viewer renders the redirected data: URL
  for (const part of ["manifest", "enrollment"]) {
    const a = el("a", i18n(part), { href: "#" });
    a.addEventListener("click", (e) => {
      e.preventDefault();
      browser.tabs.create({
        url: `${JSON_ORIGIN}/${part}/${encodeURIComponent(entry.key)}`,
      });
      window.close();
    });
    linkList.append(a);
  }
  const explorer = new URLSearchParams({ q: entry.fqdn, host: entry.fqdn });
  linkList.append(link(`${EXPLORER}?${explorer}`, i18n("explorer")));
  details.append(el("summary", i18n("advanced")), linkList);
  section.append(details);
  return section;
}

document.addEventListener("DOMContentLoaded", async () => {
  const params = new URLSearchParams(location.hash.slice(1));
  const warnings = JSON.parse(params.get("warnings") ?? "{}");
  for (const id in warnings) {
    const warning = document.createElement("div");
    warning.id = `warning-${id}`;
    warning.classList.add("warning");
    warning.textContent = renderers[id].message(...warnings[id]);
    if (renderers[id].button) {
      const button = renderers[id].button(...warnings[id]);
      warning.prepend(button);
    }
    document.body.prepend(warning);
  }

  const main = document.getElementById("origins");
  const origin = params.get("origin");
  // Leading rows: "Verification" with a tick, "not available", "in progress"
  // or a cross plus "Error" rows with the code. The site is in the URL bar.
  const [tab] = await browser.tabs.query({ active: true, currentWindow: true });
  const title = tab?.id
    ? await browser.pageAction.getTitle({ tabId: tab.id })
    : "";
  const rows = [];
  const embedded = [];
  if (origin) {
    rows.push([i18n("verification"), icon(true)]);
  } else if (title === i18n("webcatVerificationFailed")) {
    rows.push([i18n("verification"), icon(false)]);
    // The error page carries the code and host in its fragment. In a frame,
    // the tab's own URL is the parent's, so look at every frame of the tab.
    const errorPage = browser.runtime.getURL("pages/error.html");
    const frames = tab?.id
      ? await browser.webNavigation.getAllFrames({ tabId: tab.id })
      : [];
    for (const frame of frames ?? []) {
      if (!frame.url.startsWith(errorPage)) continue;
      const p = new URLSearchParams(new URL(frame.url).hash.slice(1));
      const host = p.get("host") ?? "";
      const where = frame.frameId === 0 ? "" : ` (${host})`;
      rows.push([i18n("error"), `${p.get("code") ?? "UNKNOWN"}${where}`]);
      if (frame.frameId !== 0)
        embedded.push(embeddedRow(host, undefined, false));
    }
  } else if (title === i18n("webcatIsVerifying")) {
    rows.push([i18n("verification"), i18n("verificationInProgress")]);
  } else if (
    title === i18n("webcatNotEnrolled") ||
    title === i18n("webcatPartiallyVerified")
  ) {
    rows.push([i18n("verification"), i18n("verificationNotAvailable")]);
  } else {
    rows.push([i18n("verification"), title]);
  }

  // Verified embedded origins: a row each in the main list, details below
  const frames = params.getAll("frame").map((f) => JSON.parse(f));
  const framesStored = await Promise.all(frames.map(loadStored));
  frames.forEach((f, i) => embedded.push(embeddedRow(f.fqdn, framesStored[i])));

  if (origin) {
    const delegation = params.get("delegation");
    if (delegation) {
      rows.push([i18n("delegation"), delegation]);
    }
    const entry = JSON.parse(origin);
    main.append(
      await renderOrigin(entry, await loadStored(entry), rows, embedded),
    );
  } else {
    main.append(keyValueList([...rows, ...embedded]));
  }

  if (frames.length > 0) {
    const details = el("details");
    details.append(el("summary", i18n("embeddedDetails")));
    for (const [i, frame] of frames.entries()) {
      details.append(
        await renderOrigin(frame, framesStored[i], [
          [i18n("embedded"), frame.fqdn],
        ]),
      );
    }
    main.append(details);
  }
});
