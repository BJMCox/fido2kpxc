// Adds a copy button to the top right of every code box.
(function () {
  document.querySelectorAll("pre > code").forEach(function (code) {
    var button = document.createElement("button");
    button.type = "button";
    button.className = "copy";
    button.textContent = "Copy";
    button.setAttribute("aria-label", "Copy the command");
    button.addEventListener("click", function () {
      navigator.clipboard.writeText(code.textContent).then(function () {
        button.textContent = "Copied";
      }, function () {
        button.textContent = "Press ⌘C";
        getSelection().selectAllChildren(code);
      });
      setTimeout(function () { button.textContent = "Copy"; }, 1500);
    });
    code.parentElement.appendChild(button);
  });
})();
