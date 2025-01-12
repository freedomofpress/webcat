# Web-based Code Assurance & Transparency (WEBCAT)
![webcat logo dark](./docs/icons/dark/256/webcat.png#gh-dark-mode-only)
![webcat logo light](./docs/icons/light/256/webcat.png#gh-light-mode-only)

The purpose of this project is to showcase an architectural framework for providing blocking code signing, integrity and transparency checks for browser-based single page applications.

Webcat is:
 1. [A list server](./list_server/)
 2. [A few processing scripts](./jobs/)
 3. [A transparency server](./transparency_server/) (as a [Trillian](https://github.com/google/trillian) personality)
 4. [A Firefox (v2) extension](./extension/)
 5. [A signing script](./signing/)
 6. [Deployment infrastructure](./deploy/)
 7. [Demo and application examples](./demo/)


See [The long and winding road to safe browser-based cryptography](https://securedrop.org/news/browser-based-cryptography/) for additional context.

## Introduction
In the past decade, web applications have undergone a significant evolution, marked by a proliferation of features, enhanced functionality, and optimization. Support for WebAssembly in browsers has allowed more low-level options, and application packaging such as Electron has offered easier portability. Services like WhatsApp Web, Wire, ProtonMail, crypto wallets, and encrypted collaboration suites are now commonly used, increasing reliance on web-based platforms.

In contrast to all these efforts, in-browser encryption is still dependent on server trust: in the case of its successful compromise, it is trivial to serve compromised code. Thus, using a web application for encryption still poses most of the traditional risks associated with a classic data breach.

Detecting such attacks proves exceptionally challenging. They can be meticulously tailored to a specific user and a particular page load, rendering them almost certain to go unnoticed. As such, their feasibility is technically fully possible, either by attackers who compromises the services, or by the services administrators themselves, and are almost guaranteed to go undetected, since they might leave no traces at all. 

The scope of this work is to propose a common solution for preventing, in the most favorable scenario, or at least detecting, in the worst possible conditions, these attacks. The aim is to achieve this not by reinventing cryptography primitives, but rather engineering together the state-of-the-art in software signing (SCITT, SigStore), PKI technologies (signing, revocation, transparency, etc), browser security (CSP) and update schemes (TUF).

The final goal is to implement a working proof-of-concept in the form of a browser addon for Tor Browser, with the purpose of reaching upstream support in the next phases of this project. Ultimately, the server serving the web application should become untrusted, or at least as untrusted as any server with dedicated, signed clients is. Drawing a parallelism: Signal requires signed client applications on any platform a user wants to use it. The clients interact with Signal servers, which are mostly cloud based and distributed around the world. These servers are still in a privileged position, as they deliver messages and attachments, have access to authentication information and know access patterns to their API. While it is assumed that Signal servers will never be able to break the confidentiality of messages and certain sealed or absent metadata, nonetheless they could still mount targeted attacks, by choosing not to deliver messages, analyzing access patterns, distributing the wrong keys, and so on. Some of these attacks might be detectable, some not, but it is imperative that the core properties hold.

## Context
This project started as a requisite for SecureDrop, an open-source whistleblowing platform, to implement robust end-to-end encryption. The contextual significance lies in the fact that whistleblowing platforms constitute a subset of browser-based encryption applications, which typically necessitates additional considerations to comprehensively uphold privacy and anonymity.

The most crucial security aspect of any whistleblowing system is to preserve the anonimity of the leaker at all costs. SecureDrop fulfills this critical requirement by exclusively operating as a Tor-based Hidden Service, accessible solely to users employing the Tor Browser. Immediately afterwards, there are the other two most important requirements: the confidentiality of the leaked material and plausible deniability on the leaker side.
The notions of privacy, anonymity and plausible deniability significantly influences some design choices: this is clearly specified and explained when occurs.


## Target applications
Security and authentication measures such as Transport Layer Security (TLS) or CSP (Content Security Policy), albeit very different between each other both in therms of purposes and architecture level, are aimed at any website on the internet. TLS is even more generic, in the sense that it can be use to encapsulate any network traffic even in non HTTP-based protocols, and as such its infrastructure needs to scale in a future-proof way for tens of billions of devices and certificates. CSP does not have the same complexity and scalability issues, but its ultimate goal its still to be deployed on any website designed for end users' browsers.

That is not the case for this problem: the proposal is only useful for a very specific, yet security critical, subset of web applications. The given examples, from CryptPad, to Wire or even MEGA differs from traditional web services because their core marketing and security property is to protect the confidentiality of users' information even from themselves, meaning the service providers. As such, the intended receiver of those information are either the user themselves, as in the case of encrypted backup, pads or office suites, or other, hopefully authenticated peers.

Contrarily, the prevalent scenario on the web is the opposite: the service provider is the ultimate receiver and maintainer of user information, which is rendered accessible and editable through a web application. This is particularly evident in cases where the website predominantly serves as a frontend for customers, be it a bank, an health institution, a government service and so on.

## Brief history
The problem has been known in the security community for more than a decade and often bringing heated discussions with a lot of important points. [A good summary of that was made by Thomas Ptacek, while working at Matasano Security, in 2011](http://web.archive.org/web/20110925120934/http://www.matasano.com/articles/javascript-cryptography/), in a blog post called "Javascript Cryptography Considered Harmful". At the time the discussion was more focused in which role JavaScript could have to add transport security: TLS was not widely deployed, certificates where costly, automation was scarce. As a consequence the idea of using JavaScript to protect mostly against man-in-the-middle attacks was a hyped research topic. [The idea of hashing passwords client-side via JavaScript on login may date as far back as 1998](https://security.stackexchange.com/questions/53594/why-is-client-side-hashing-of-a-password-so-uncommon), with many of the limitations already taken into account. While the whole idea of adding transport encryption via JavaScript could help against passive attackers, nothing can stop active attackers who can proactively change any part of the code while in transit, and there are no possible patches against this. This is what Thomas defined in his article as the _chicken-egg problem_:

> If you don't trust the network to deliver a password, or, worse, don't trust the server not to keep user secrets, you can't trust them to deliver security code. The same attacker who was sniffing passwords or reading diaries before you introduce crypto is simply hijacking crypto code after you do.


JavaScript engines in browsers at the time also lacked the environment to enable programmers to perform crypto securely: from the lack of a safe CSPRNG to constant time functions. Furthermore, JavaScript is what Thomas defined as a _{malleable runtime_:

> We mean you can change the way the environment works at runtime. And it's not bad; it's a fantastic property of a programming environment, particularly one used "in the small" like Javascript often is. But it's a real problem for crypto.
>
> The problem with running crypto code in Javascript is that practically any function that the crypto depends on could be overridden silently by any piece of content used to build the hosting page. Crypto security could be undone early in the process (by generating bogus random numbers, or by tampering with constants and parameters used by algorithms), or later (by spiriting key material back to an attacker), or --- in the most likely scenario --- by bypassing the crypto entirely.
>
>There is no reliable way for any piece of Javascript code to verify its execution environment. Javascript crypto code can't ask, "am I really dealing with a random number generator, or with some facsimile of one provided by an attacker?" And it certainly can't assert "nobody is allowed to do anything with this crypto secret except in ways that I, the author, approve of". These are two properties that often are provided in other environments that use crypto, and they're impossible in Javascript.


Features to solve most of these problems are now guaranteed in all major web browsers and the internet infrastructure has progressed too:
 * TLS is now computationally cheap, certificates are mostly free, automatic deployment and renew is the norm, overall addressing all the transport encryption concerns.
 * [The Web Crypto API](https://developer.mozilla.org/en-US/docs/Web/API/Web_Crypto_API) exposes an API to securely perform cryptopgraphy operations in JavaScript (albeit there is the acknowledgement that JS-based cryptopgraphy might still be more fragile and vulnerable, for instance to cross-tab side-channel attacks).
 * The Content Security Policy (now on the works to be tailored for WebAssembly too) gives a server control over most of the _malleable_ features on the JavaScript runtime, such as preventing certain scripts, inline code and similar. [True remote attestation for a browser environment is not available, but whether that would be a positive feature is currently debated](https://en.wikipedia.org/wiki/Web_Environment_Integrity).


Many of the challenges hindering the implementation of secure JavaScript cryptography have undergone significant resolution over the years, thanks to extensive work and research. With the widespread adoption of Transport Layer Security (TLS), the focal point has shifted from transport security to server security. The current objective, as opposed to encrypting or obfuscating data during transit to the server, is to implement end-to-end encryption to shield such data from the server itself. While the threat model and technology have evolved, the enduring _chicken-egg problem_ persists, albeit within a different context.

The fundamental concern remains: how can one trust the server delivering the encryption code to consistently act in good faith and not serve a malicious version? The general approach is reasonably secure against passive attackers; once data is successfully encrypted, it cannot be solely retrieved from the server's memory, as is the case with classic, single-point-in-time data leaks or server seizures due to legal orders. However, an active attacker possesses myriad options to undermine this protection.

Experiments and progresses since that article are explored in Section \ref{section:sota_code_integrity}.

The blog post closes with a recommendation we are now exploring:
    Check back in 10 years when the majority of people aren't running browsers from 2008.
 

## High level implementation proposal
### Browser preload list
There is the need to preload in browsers a list with the domains that requires the code integrity verification and at least some kind of cryptographic proof that such domains are serving the correct package from the set of correct possible developers.
To do so, we can develop a service similar to the HSTS preload list, but more transparent and auditable, so that, even if that is a single entity and a possible single point of failure, such failure are detected systematically. Furthermore, while the HSTS preload list must just contain the domain and the domain itself brings the information that such a website must use TLS, for the scope of this project we expect this list to be a slightly more complicated data structure, which size we should aim to minimize as much as possible (which is, keep there only the minimum required to perform successfully the cryptographic verification required later).

#### Domain setup

![Domain setup chart](https://github.com/lsd-cat/webcat/blob/main/docs/images/domain_setup.drawio.png?raw=true)

As depicted in the figure we can imagine a system with the following structure:
 1. Website owner of www.example.com wants to setup code integrity on their website
 2. It is the first time www.example.com is being added in the code integrity list
 3. Website owner configure such an application on the root of their virtual host (on /) and sets up the proper header (and TLS)
 4. The proper headers includes a strict CSP policy (such as that suggested in the WAIT paper) and information about the application, including the project url/name as it gets signed in SigStore, and who are valid signers for such a project in SigStore terms (so dev1@github.com, dev2@gmail.com and so on) and a contact email
 5. Website owner submits www.example.com to our validator service for code integrity
 6. Validator service checks that the domain is not already in the list, and checks that the headers served by www.example.com are valid. We consider this as a ‘trust on first submission’ but we need checks in place to avoid hack and then squat, causing denial of services and possible persistent damages (ie: if a website is compromised, an attacker must not be able to force browsers to expect a compromised or bogus application forever, thus we should probably have ’grace’ period before the changes are actually committed)
 7. Validator publishes the request to at least 2 Transparency Logs and sends the inclusion promises back to the submitter.
 8. Validator adds the required information to the preload list (which data structure TBD) and publishes it.
 9. Admin adds the inclusion promises as HTTP Headers

#### Browser setup
1. Periodically, browser/plugin vendors compile in a reproducible way the necessary data structures from the public list
2. Sign and log it somewhere
3. Distribute it to the clients (weekly? just binary incremental diff?)

#### User validation

![Browser verification chart](https://github.com/lsd-cat/webcat/blob/main/docs/images/browser_verification.drawio.png?raw=true)

1. Users type www.example.com in browser
2. Browser starts fetching and downloading the website assets
3. In parallel, browser checks whether an entry in the list for www.example.com exists
4. If an entry exists, continue downloading and preparing the app but block JS execution
5. Check that www.example.com headers conform with the expectations: strict CSP, application/authors matches the list, inclusion promises are for cryptographically valid, trusted and diverse
6. If step 5 succeeds, perform SigStore validation (including the due revocation checks) on the project/authors specified in the list
7. If everything succeeds, allow JS execution and run the application

### Key questions
 * Proper data structure for the list: minimize and fast lookups (bloom filter + double hashtable? hash(site)->hash(signing identities/app) then the website provide the actual info and we use the list just for verification)
 * Proper transparency/validation architecture
 * Lookup speed is crucial: deciding whether a website is in the list or not should not add delay (otherwise it would slow down all the browsing experience). If a website is in the list, then a reasonable load delay to perform the validation is acceptable
 * Domains change ownerships and websites can change applications. How to manage transitions in the list?


### Hidden Services [extra]
Onion names are very different compared to traditional domains: they are expected to never be reused and the owner can prove ownership cryptographically since they must own the corresponding private key. This simplifies some things, but complicates others: we might imagine that some hidden services do not want to be publicly advertised but that is a requirement both for the preload lists and the transparency log.

However, a similar submission mechanism is possible if we change the overall requirements. It would still be partially auditable, but only from the hidden service owners themselves instead of globally.

Multiple options here: do we want to keep everything secret or not?
 * If not: the list cannot verify submissions but can still enforce them later on (we can require website owners to sign using the onion name private ley)
 * If yes: we can perform validation on the server side but then never disclose the plaintext info to the public list (this makes the list server even more as a single point of failure): such as owner sends name.onion, blind signature using name.onion privkey(identities/app), unblinding factor. List server checks the correct signature for the hidden service, but then logs only hash(name.onion), blindsig(identity/app) and includes that in the list/ct logs. Website owners can verify the proper inclusions, and users can only when they visit name.onion and match the corresponding hashlist.



