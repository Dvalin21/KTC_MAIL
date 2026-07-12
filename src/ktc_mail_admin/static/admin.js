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
