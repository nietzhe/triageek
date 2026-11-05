(function () {
  "use strict";

  var button = document.getElementById("create-button");
  var counter = document.getElementById("selected-count");
  var selectAll = document.getElementById("select-all");
  var boxes = Array.prototype.slice.call(document.querySelectorAll(".row-select"));

  function refresh() {
    if (!button) return;
    var count = boxes.filter(function (box) { return box.checked; }).length;
    counter.textContent = String(count);
    button.disabled = count === 0;
    
    if (selectAll) {
      selectAll.checked = boxes.length > 0 && count === boxes.length;
      selectAll.indeterminate = count > 0 && count < boxes.length;
    }
  }

  boxes.forEach(function (box) { box.addEventListener("change", refresh); });
  if (selectAll) {
    selectAll.addEventListener("change", function () {
      boxes.forEach(function (box) { box.checked = selectAll.checked; });
      refresh();
    });
  }
  refresh();

  var group = document.querySelector("[data-action-group]");
  if (group) {
    var panels = Array.prototype.slice.call(group.querySelectorAll("details.action"));
    panels.forEach(function (panel) {
      panel.addEventListener("toggle", function () {
        if (!panel.open) return;
        panels.forEach(function (other) { if (other !== panel) other.open = false; });
      });
    });
  }

  // save as PDF.
  var printButton = document.querySelector("[data-print]");
  if (printButton) printButton.addEventListener("click", function () { window.print(); });
})();
