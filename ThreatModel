# Schematic Threat Model

### Outside WEBCAT
| ID | Compromised Asset | Attack  | Target | Expected Security Property | Explanation | 
|----|---|---|---|---|---|
|  1 | Frontend/CDN | Serve compromised webapp | Domain-specific end users | Detect and block before any script execution (optional: report it) | The browser component must detect an invalid asset as part of the SigStore signed app prior any execution. |
|  2 | Frontend/CDN/DNS | Swap application in preload-list  | Domain-specific end users  | Delay X days, detect via log auditing, stop it if action taken within X days | The submission server and transparency log must detect the domain was already enrolled, use the migration procedure: log the migration start, notify emails, require a migration confirmation after a X to complete and log it. |
|  3 | Signed application |  Supply chain attack, malicious code lands with a valid signature in the web app | Application-specific (multiple domains) end users | End user is compromised, attack is undetected while in progress. If the malicious code gets discovered, the Rekor Artifacts log must have evidence of it. | Same case that with plain SigStore, backdoored artifact is logged in Rekor with precise date and metadata. Artifact should eventually be available too for posthumous inspection. |
|  4 | Developer identity | Supply chain attack, malicious application has a valid signature. | (Multiple) applications (multiple domains) end users | Depends on signing policy: more than a single developer signature might be required. Otherwise, user is compromised but attack is detectable posthumously, both via the Fulcio Log and the Rekor Log. | If signing policy is N of M developers, app must not be executed with only a single spoofed identity (and possibly report). If invalid app is signed, Fulcio and Rekor Logs must have evidence. |
|  5 | Dynamic JS loading | Application vulnerability (Example: XSS or broken app logic) | (Multiple) applications (multiple domains) end users | Any dynamic Javascript code load or execution must be prevented. | Apply strict CSP, disallow evals and any external source. (TODO: disallow same source unsigned files) |


### Within WEBCAT
| ID | Compromised Asset | Attack  | Target | Expected Security Property | Explanation | 
|----|---|---|---|---|---|
|  6 | WEBCAT Submission Server | Maliciously change the WEBCAT preload-list | All end users | If a WEBCAT list entry does not have a valid WEBCAT Log inclusion proof, then it must be rejected, both by the WEBCAT list builder and all end users. | Compromising/backdooring the submission server should not bring any real advantage to an attacker by itself. Everything that changes the list must be logged in the WEBCAT Transparency Log and it should also double perform some of the checks (such as, no duplicate entries, live headers matching, etc). |
|  7 | WEBCAT Transparency Log | Alter the transparency log to edit/remove entries | All end users | Monitors must be able to catch any tampering by checking the consistency proofs (and eventually rebuilding the full tree preiodically). | It is virtually the same as attacking a Certificate Trabnsparency Log: it must be detectable and not useful by itself (but rhather in conjunction with a CA compromise) |
|  8 | WEBCAT Compiled Preload List building/signing server | Modify the preload-list before it gets shipped to end-users| All end users | WEBCAT compiled preload-list must be repoducible, logged to Rekor and signed. In case of compromise of the build server, monitors must be able to detect a mismatch between the WEBCAT Transparency Log and the built lists. | Attacks can be detected quickly by active monitors or eventually posthumously thanks to the Rekor log |
|  9 | WEBCAT Browser Plugin | Supply chain attack in WEBCAT code | All end users | Dependant on the plugin distribution channel (Mozilla, Chrome Store, built-in) | Out of scope for WEBCAT, dependant on the browser supply chain. |

## Sample Threats
| Threat | Explanation/Mitigation |
|---|---|
| JS-based Browser Exploit | Depends how exploit gets deployed, can be 1, 2, 3, 4, 5. Worst cases: (3, partial-4): it runs but is detectable and know posthumously. Best cases (1, 2, 5): execution is fully prevented. |
| Hacked Server/Malicious Admin | Always prevented (cases 1, 2, 5). |
| Cross-tab/window Side-Channel Attack | Out of scope: cannot be mitigated by code-integrity systems. Worst case: (crypto) info/keys leak. Best case: general JavaScript execution is allowed only for WEBCAT applications. |
