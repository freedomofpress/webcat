// record console logs, uncaught errors, and uncaught rejections
window.capture = { logs: [], errors: [], rejections: [] };
(function (capture) {
  function relative(url) {
    if (!url) return '';
    return URL.parse(url, location.href).pathname;
  }
  const log = console.log;
  console.log = function () {
    top.postMessage({ type: 'logs', value: [...arguments] }, "*");
    log.apply(console, arguments);
  }
  window.addEventListener('error',
    ({ error }) => top.postMessage({ type: 'errors', value: [ error.toString(), relative(error.fileName) ] }, "*"));
  window.addEventListener('unhandledrejection',
    ({ reason }) => {
      if (reason instanceof Error) {
        top.postMessage({ type: 'rejections', value: [ reason.toString(), relative(reason.fileName) ] }, "*");
      } else {
        top.postMessage({ type: 'rejections', value: [ reason.toString() ] }, "*");
      }
    });
  window.addEventListener('message',
    ({ data }) => capture[data.type].push(data.value));
}(window.capture));
