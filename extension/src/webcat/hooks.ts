export function getHooksInjector(
  signing_key: JsonWebKey,
  encryption_key: JsonWebKey,
): string {
  // Generate dynamically injected script content
  const scriptContent = `
        function injectExternalScript(scriptContent) {
            const blob = new Blob([scriptContent], { type: "application/javascript" });
            const scriptURL = URL.createObjectURL(blob);

            const script = document.createElement("script");
            script.src = scriptURL;
            script.onload = function () {
                URL.revokeObjectURL(scriptURL);
                this.remove();
            };

            (document.head || document.documentElement).appendChild(script);
        }

        // Hooks script with embedded JWK keys
        const hooksScript = \`
            (async function() {
                console.log("Hook script executing...");
                const signingKeyJWK = ${JSON.stringify(signing_key)};
                const encryptionKeyJWK = ${JSON.stringify(encryption_key)};

                // Import public keys in the document context
                const signingKey = await crypto.subtle.importKey(
                    "jwk",
                    signingKeyJWK,
                    { name: "Ed25519" },
                    true,
                    ["verify"]
                );

                const encryptionKey = await crypto.subtle.importKey(
                    "jwk",
                    encryptionKeyJWK,
                    { name: "X25519" },
                    true,
                    []
                );

                console.log("✅ Successfully imported public keys!");
                console.log("Signing Key:", signingKey);
                console.log("Encryption Key:", encryptionKey);
            })();
        \`;

        injectExternalScript(hooksScript);
    `;
  return scriptContent;
}
