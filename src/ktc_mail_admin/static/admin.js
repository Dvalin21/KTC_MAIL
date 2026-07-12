// KTC Mail admin — all client JS. No inline handlers (CSP script-src 'self').

// Confirm dialogs: any form with data-confirm prompts before submit.
document.addEventListener("submit", function (e) {
  var form = e.target;
  if (!form || !form.hasAttribute("data-confirm")) return;
  if (!window.confirm(form.getAttribute("data-confirm"))) {
    e.preventDefault();
  }
});

// Password-change dialog (users page).
function showPasswordForm(email) {
  document.getElementById("pw-email").value = email;
  document.getElementById("pw-input").value = "";
  document.getElementById("password-dialog").style.display = "flex";
}
function hidePasswordForm() {
  document.getElementById("password-dialog").style.display = "none";
}

// Backup destination selector: show credential fields only for env-backed
// targets (s3/b2). Local + SFTP need none.
document.addEventListener("DOMContentLoaded", function () {
  var sel = document.getElementById("backend");
  var cred = document.getElementById("cred-fields");
  if (!sel || !cred) return;
  function toggle() {
    cred.style.display = (sel.value === "s3" || sel.value === "b2")
      ? "block" : "none";
  }
  sel.addEventListener("change", toggle);
  toggle();
});
