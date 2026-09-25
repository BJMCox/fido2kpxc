// Tells visitors on other systems, once per browser, that the app runs only on macOS.
(function () {
  var KEY = "fido2kpxc-os-notice-seen";
  var platform = (navigator.userAgentData && navigator.userAgentData.platform) ||
    navigator.platform || navigator.userAgent;
  // iPadOS Safari reports a Mac platform, so touch support tells the two apart.
  var mac = /mac/i.test(platform) && navigator.maxTouchPoints < 2;
  if (mac) return;
  try {
    if (localStorage.getItem(KEY)) return;
    localStorage.setItem(KEY, "1");
  } catch (e) {
    // Without storage the notice shows on every visit, which is better than never.
  }

  var dialog = document.createElement("dialog");
  dialog.setAttribute("aria-labelledby", "os-notice-title");
  dialog.style.cssText = "max-width:420px;border:0;border-radius:14px;padding:24px;" +
    "background:var(--panel,#2c3344);color:var(--text,#f5f5f7);font:inherit;";
  dialog.innerHTML =
    '<h2 id="os-notice-title" style="margin:0 0 10px;font-size:20px">fido2kpxc needs a Mac</h2>' +
    '<p style="margin:0 0 20px">fido2kpxc runs only on macOS 13 or later on a Mac with Apple silicon. ' +
    "It will not work on this device, but you can read on.</p>" +
    '<form method="dialog" style="text-align:right;margin:0">' +
    '<button style="font:inherit;font-weight:600;padding:9px 18px;border-radius:10px;cursor:pointer;' +
    'border:0;background:var(--gold,#f0b43a);color:var(--bg,#232937)">Continue</button></form>';
  document.body.appendChild(dialog);
  if (dialog.showModal) {
    dialog.showModal();
  } else {
    dialog.setAttribute("open", "");
  }
})();
