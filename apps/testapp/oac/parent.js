// Embeds the same-site frame given by ?frame= and records what it manages to do to us
window.oac = { originAgentCluster: window.originAgentCluster };
document.domain = location.hostname; // opt in to relaxation; a no-op when origin-keyed
addEventListener("message", ({ data }) => {
    if ("module" in data) window.oac.moduleReceived = data.module;
    if ("results" in data) Object.assign(window.oac, data.results);
});
addEventListener("messageerror", () => { window.oac.messageError = true; });
addEventListener("DOMContentLoaded", () => {
    const iframe = document.createElement("iframe");
    iframe.src = new URLSearchParams(location.search).get("frame");
    document.body.appendChild(iframe);
});
