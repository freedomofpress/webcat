window.addEventListener("DOMContentLoaded", () => {
    const params = new URLSearchParams(location.search);
    const iframe = document.querySelector("iframe");
    iframe.src = params.get("url");
});
