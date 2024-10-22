function injectExternalScript(file) {
  const script = document.createElement('script');
  script.src = chrome.runtime.getURL(file);
  script.onload = function() {
    this.remove(); // Remove the script element after it's been executed
  };
  (document.head || document.documentElement).appendChild(script);
}

injectExternalScript('hooks/hook.js');