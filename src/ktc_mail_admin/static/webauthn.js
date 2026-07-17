// KTC Mail — WebAuthn browser glue (no external libs; CSP-safe, offline).
// Converts between the server's base64url options/responses and the
// ArrayBuffer values navigator.credentials expects. Mirrors the wire format
// produced by @simplewebauthn/browser so py_webauthn verifies it directly.
(function () {
  "use strict";

  function b64urlToBuf(s) {
    s = s.replace(/-/g, "+").replace(/_/g, "/");
    while (s.length % 4) s += "=";
    const bin = atob(s);
    const buf = new Uint8Array(bin.length);
    for (let i = 0; i < bin.length; i++) buf[i] = bin.charCodeAt(i);
    return buf;
  }
  function bufToB64url(buf) {
    const bytes = new Uint8Array(buf);
    let bin = "";
    for (let i = 0; i < bytes.length; i++) bin += String.fromCharCode(bytes[i]);
    return btoa(bin).replace(/\+/g, "-").replace(/\//g, "_").replace(/=+$/, "");
  }

  function prepRegister(opts) {
    opts.challenge = b64urlToBuf(opts.challenge);
    opts.user.id = b64urlToBuf(opts.user.id);
    if (opts.excludeCredentials) {
      opts.excludeCredentials = opts.excludeCredentials.map((c) => ({
        ...c,
        id: b64urlToBuf(c.id),
      }));
    }
    return opts;
  }
  function prepAuth(opts) {
    opts.challenge = b64urlToBuf(opts.challenge);
    if (opts.allowCredentials) {
      opts.allowCredentials = opts.allowCredentials.map((c) => ({
        ...c,
        id: b64urlToBuf(c.id),
      }));
    }
    return opts;
  }

  async function postForm(url, data) {
    const fd = new FormData();
    for (const k in data) fd.append(k, data[k]);
    const r = await fetch(url, { method: "POST", body: fd });
    return r.json();
  }
  function status(msg) {
    document
      .querySelectorAll("#wa-status")
      .forEach((e) => (e.textContent = msg));
  }

  window.startRegister = async function () {
    status("Waiting for security key…");
    try {
      const opts = await postForm("/settings/webauthn/register/begin", {
        csrf_token: window.WA_CSRF,
      });
      if (opts.error) {
        status(opts.error);
        return;
      }
      const cred = await navigator.credentials.create({
        publicKey: prepRegister(opts),
      });
      const payload = {
        id: cred.id,
        rawId: bufToB64url(cred.rawId),
        response: {
          attestationObject: bufToB64url(cred.response.attestationObject),
          clientDataJSON: bufToB64url(cred.response.clientDataJSON),
          transports: cred.response.getTransports
            ? cred.response.getTransports()
            : [],
        },
        type: cred.type,
        clientExtensionResults: cred.clientExtensionResults,
        name: window.prompt("Name this security key (e.g. YubiKey):") || "",
      };
      const fd = new FormData();
      fd.append("csrf_token", window.WA_CSRF);
      fd.append("response", JSON.stringify(payload));
      const r = await fetch("/settings/webauthn/register/finish", {
        method: "POST",
        body: fd,
      });
      const j = await r.json();
      if (j && j.ok) {
        window.location.href = "/settings?msg=Security+key+registered";
      } else {
        status((j && j.error) || "Registration failed");
      }
    } catch (e) {
      status("Registration cancelled or failed: " + e.message);
    }
  };

  window.startLogin = async function () {
    status("Waiting for security key…");
    try {
      const opts = await postForm("/login/webauthn/begin", {});
      if (opts.error) {
        status(opts.error);
        return;
      }
      const cred = await navigator.credentials.get({
        publicKey: prepAuth(opts),
      });
      const payload = {
        id: cred.id,
        rawId: bufToB64url(cred.rawId),
        response: {
          authenticatorData: bufToB64url(cred.response.authenticatorData),
          clientDataJSON: bufToB64url(cred.response.clientDataJSON),
          signature: bufToB64url(cred.response.signature),
          userHandle: cred.response.userHandle
            ? bufToB64url(cred.response.userHandle)
            : null,
        },
        type: cred.type,
        clientExtensionResults: cred.clientExtensionResults,
        csrf_token: window.WA_CSRF,
      };
      const r = await fetch("/login/webauthn/finish", {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify(payload),
      });
      const j = await r.json();
      if (j && j.ok) {
        window.location.href = "/";
      } else {
        status((j && j.error) || "Security key login failed");
      }
    } catch (e) {
      status("Security key login cancelled or failed: " + e.message);
    }
  };
})();
