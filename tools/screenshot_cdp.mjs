#!/usr/bin/env node
// Headless screenshot capture for KTC Mail admin UI — zero npm deps.
// Uses the DevTools Protocol over the global WebSocket (Node 22+).
// Usage: node screenshot_cdp.mjs <baseUrl> <outDir> <adminEmail> <adminPass>
import { writeFileSync, mkdirSync } from "node:fs";
// Node 22 exposes WebSocket globally — no npm deps needed.

const [base, outDir, email, pass] = process.argv.slice(2);
const BASE = base.replace(/\/$/, "");
const CDP = "http://127.0.0.1:9222"; // chrome remote-debugging port
mkdirSync(outDir, { recursive: true });

const ver = await (await fetch(`${CDP}/json/version`)).json();
const ws = new WebSocket(ver.webSocketDebuggerUrl);
const listeners = new Map();
let id = 0;
function send(method, params = {}) {
  return new Promise((resolve) => {
    const msgId = ++id;
    listeners.set(msgId, resolve);
    ws.send(JSON.stringify({ id: msgId, method, params }));
  });
}
ws.addEventListener("message", (d) => {
  const m = JSON.parse(d.data.toString());
  if (m.id && listeners.has(m.id)) {
    listeners.get(m.id)(m);
    listeners.delete(m.id);
  }
});
await new Promise((r) => ws.addEventListener("open", r));

const targets = await (await fetch(`${CDP}/json`)).json();
let page = targets.find((t) => t.type === "page") || targets[0];
const sessionWs = new WebSocket(page.webSocketDebuggerUrl);
const sl = new Map();
let sid = 0;
function ssend(method, params = {}) {
  return new Promise((resolve) => {
    const mId = ++sid;
    sl.set(mId, resolve);
    sessionWs.send(JSON.stringify({ id: mId, method, params }));
  });
}
sessionWs.addEventListener("message", (d) => {
  const m = JSON.parse(d.data.toString());
  if (m.id && sl.has(m.id)) { sl.get(m.id)(m); sl.delete(m.id); }
});
await new Promise((r) => sessionWs.addEventListener("open", r));
await ssend("Page.enable");

async function navigate(url) {
  await ssend("Page.navigate", { url });
  // Poll until the new document reports fully loaded (no event-race).
  for (let i = 0; i < 50; i++) {
    const st = await ssend("Runtime.evaluate", { expression: "document.readyState" });
    if (st.result?.result?.value === "complete") break;
    await new Promise((r) => setTimeout(r, 100));
  }
  await new Promise((r) => setTimeout(r, 800));
}
async function shoot(name) {
  await ssend("Runtime.evaluate", { expression: "new Promise(requestAnimationFrame)" }).catch(() => {});
  // Capture twice: the first frame can still be the previous navigation's
  // compositor output; the second reliably reflects the current page.
  let r = await ssend("Page.captureScreenshot", { format: "png", fullPage: true });
  await ssend("Runtime.evaluate", { expression: "new Promise(requestAnimationFrame)" }).catch(() => {});
  r = await ssend("Page.captureScreenshot", { format: "png", fullPage: true });
  writeFileSync(`${outDir}/${name}.png`, Buffer.from(r.result.data, "base64"));
  console.log("shot", name);
}

// 1) Public login page (no auth)
await navigate(`${BASE}/login`);
await shoot("login");

// 2) Self-service login page (public)
await navigate(`${BASE}/self/login`);
await shoot("self_login");

// 3) Log in by filling + submitting the real form (browser stores the
//    session cookie via the app's normal redirect flow).
await navigate(`${BASE}/login`);
const loginJs = `
(async () => {
  const token = document.querySelector('input[name="csrf_token"]')?.value || "";
  const fd = new FormData();
  fd.set("csrf_token", token);
  fd.set("email", ${JSON.stringify(email)});
  fd.set("password", ${JSON.stringify(pass)});
  try {
    const r = await fetch('/login', { method: 'POST', body: fd, credentials: 'include' });
    return JSON.stringify({ status: r.status, cookie: document.cookie });
  } catch (e) {
    return JSON.stringify({ error: String(e) });
  }
})()
`;
const res = await ssend("Runtime.evaluate", { expression: loginJs, awaitPromise: true });
console.log("login result:", res.result?.result?.value);
await new Promise((r) => setTimeout(r, 1000));
const where = await ssend("Runtime.evaluate", {
  expression: "JSON.stringify({path: location.pathname, cookie: document.cookie})",
});
console.log("after-login:", where.result?.result?.value);

const pages = [
  ["dashboard", "/"],
  ["users", "/users"],
  ["dkim", "/dkim"],
  ["dns", "/dns"],
  ["certs", "/certs"],
  ["queue", "/queue"],
  ["logs", "/logs?source=ktc-admin"],
  ["logs_postfix", "/logs?source=postfix"],
  ["settings", "/settings"],
  ["spam_policy", "/spam-policy"],
  ["quarantine", "/quarantine"],
  ["backup", "/backup"],
];
for (const [name, path] of pages) {
  await navigate(`${BASE}${path}`);
  await shoot(name);
}

ssend("Browser.close");
ws.close();
sessionWs.close();
console.log("DONE");
