// record console logs, uncaught errors, and uncaught rejections
window.capture = { logs: [], errors: [], rejections: [] };
(function (capture) {
  function relative(url) {
    if (!url) return '';
    return URL.parse(url, location.href).pathname;
  }
  const log = console.log;
  console.log = function () {
    capture.logs.push([...arguments]);
    log.apply(console, arguments);
  }
  window.addEventListener('error',
    ({ error }) => capture.errors.push([ error.toString(), relative(error.fileName) ]));
  window.addEventListener('unhandledrejection',
    ({ reason }) => {
      if (reason instanceof Error) {
        capture.rejections.push([ reason.toString(), relative(reason.fileName) ]);
      } else {
        capture.rejections.push([ reason.toString() ]);
      }
    });
}(window.capture));
