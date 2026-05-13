window.addEventListener("DOMContentLoaded", function () {
    const iframe = document.createElement("iframe");
    iframe.setAttribute("srcdoc", `<html><head>
        <script src="/js/capture.js"></script>
        <script src="/js/wasm_frame.js"></script>
    </head></html>`);
    document.body.appendChild(iframe);
});
