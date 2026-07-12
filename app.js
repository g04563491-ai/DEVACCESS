/* =========================================================================
   SECTOR-9 ACCESS TERMINAL
   -------------------------------------------------------------------------
   Credentials are never stored in plaintext. Only a SHA-256 digest of the
   admin operator ID and passphrase live in this file. On submit, the
   browser hashes whatever was typed (Web Crypto API) and compares digests.
   Guest credentials work the same way, but their digests live in a
   Supabase table (guest_access) instead of hardcoded here, so they can be
   issued and revoked without editing code.
 
   IMPORTANT — read this even though the UI says "TOP SECRET":
   This is a STATIC site (GitHub Pages). There is no server to keep a
   secret from a determined visitor. Anyone can open dev tools and read
   the admin digest below, and — because there's no real backend — anyone
   holding the Supabase publishable key (which is public the moment this
   site is live) can call the same Supabase table directly and read guest
   password hashes or insert their own guest row, bypassing this screen
   entirely, UNLESS you lock the guest_access table down with real RLS
   policies (see guest_access.sql). Treat the login screen as theming and
   a speed bump, not a security boundary.
   ========================================================================= */
 
const EXPECTED_USER_HASH = "5fa4174c6f614af6121eb0d90ef3f78c3f3758c122b97dac823cb232e8e8b203";
const EXPECTED_PASS_HASH = "c73c7ba95a20de28d8b972c40ef32a8a03f5cd9a859ae8c8da56e9ee9da23aac";
 
const SUPABASE_URL = "https://vnhgnrxixwudicwqqqzu.supabase.co";
const SUPABASE_PUBLISHABLE_KEY = "sb_publishable_1QouxYIS9jrupTIWtBeG2A_RxyPawXE";
 
const GUEST_TABLE = "guest_access";
const GUEST_TTL_HOURS = 24;
 
const SESSION_KEY = "sector9_session";
 
/* ---------------------------- utilities ---------------------------- */
 
async function sha256(text) {
  const enc = new TextEncoder().encode(text);
  const digest = await crypto.subtle.digest("SHA-256", enc);
  return Array.from(new Uint8Array(digest))
    .map((b) => b.toString(16).padStart(2, "0"))
    .join("");
}
 
function pad(n) { return n.toString().padStart(2, "0"); }
 
function tickClock() {
  const el = document.getElementById("clock");
  if (!el) return;
  const d = new Date();
  el.textContent = `${pad(d.getUTCHours())}:${pad(d.getUTCMinutes())}:${pad(d.getUTCSeconds())}Z`;
}
 
function setLink(status) {
  const dot = document.getElementById("linkDot");
  const text = document.getElementById("linkText");
  if (!dot || !text) return;
  if (status === "live") {
    dot.classList.add("live");
    text.textContent = "UPLINK SECURE";
  } else {
    dot.classList.remove("live");
    text.textContent = "UPLINK STANDBY";
  }
}
 
function randomHex(byteLen) {
  return Array.from(crypto.getRandomValues(new Uint8Array(byteLen)))
    .map((b) => b.toString(16).padStart(2, "0"))
    .join("");
}
 
function randomSessionId() {
  return randomHex(4).toUpperCase();
}
 
function getSupabase() {
  if (window.__sb) return window.__sb;
  if (typeof window.supabase === "undefined") return null;
  window.__sb = window.supabase.createClient(SUPABASE_URL, SUPABASE_PUBLISHABLE_KEY);
  return window.__sb;
}
 
function escapeHtml(str) {
  return String(str)
    .replace(/&/g, "&amp;")
    .replace(/</g, "&lt;")
    .replace(/>/g, "&gt;")
    .replace(/"/g, "&quot;");
}
 
/* ---------------------------- login flow ---------------------------- */
 
let attempts = 0;
 
function logLine(container, text, cls = "") {
  const line = document.createElement("div");
  if (cls) line.className = cls;
  line.textContent = text;
  container.appendChild(line);
  container.scrollTop = container.scrollHeight;
}
 
function wait(ms) { return new Promise((r) => setTimeout(r, ms)); }
 
async function handleLogin(e) {
  e.preventDefault();
 
  const submitBtn = document.getElementById("submitBtn");
  const feedback = document.getElementById("feedback");
  const log = document.getElementById("terminalLog");
  const userInput = document.getElementById("username").value.trim();
  const passInput = document.getElementById("password").value;
 
  attempts += 1;
  document.getElementById("attemptCounter").textContent = `ATTEMPTS: ${attempts}`;
 
  submitBtn.disabled = true;
  feedback.textContent = "";
  feedback.className = "feedback";
  log.classList.add("open");
  log.innerHTML = "";
 
  logLine(log, "> initiating handshake…", "accent");
  await wait(220);
  logLine(log, "> hashing operator id (SHA-256)…");
  const userHash = await sha256(userInput);
  await wait(180);
  logLine(log, "> hashing passphrase (SHA-256)…");
  const passHash = await sha256(passInput);
  await wait(220);
  logLine(log, "> comparing digests against clearance ledger…");
  await wait(280);
 
  if (userHash === EXPECTED_USER_HASH && passHash === EXPECTED_PASS_HASH) {
    return grantAccess(log, feedback, "ADMIN", { username: userInput });
  }
 
  logLine(log, "> no local match — checking guest ledger…");
  const guest = await checkGuestCredential(userInput, passHash);
 
  if (guest) {
    return grantAccess(log, feedback, "GUEST", {
      username: userInput,
      expiresAt: guest.expires_at,
    });
  }
 
  logLine(log, "> digest mismatch — credentials rejected.", "bad");
  logLine(log, `> incident logged: attempt #${attempts} from this terminal.`, "bad");
  feedback.textContent = "ACCESS DENIED — CREDENTIALS INVALID";
  submitBtn.disabled = false;
  document.getElementById("password").value = "";
  document.getElementById("password").focus();
}
 
async function checkGuestCredential(username, passHash) {
  const sb = getSupabase();
  if (!sb || !username) return null;
 
  const nowIso = new Date().toISOString();
  const { data, error } = await sb
    .from(GUEST_TABLE)
    .select("username, password_hash, expires_at")
    .eq("username", username)
    .gt("expires_at", nowIso)
    .limit(1)
    .maybeSingle();
 
  if (error || !data) return null;
  if (data.password_hash !== passHash) return null;
  return data;
}
 
async function grantAccess(log, feedback, role, info) {
  logLine(log, "> digest match — identity confirmed.", "good");
  logLine(log, `> access granted [${role}]. loading dev panel…`, "good");
  feedback.textContent = "ACCESS GRANTED";
  feedback.classList.add("ok");
  setLink("live");
 
  const session = {
    sid: randomSessionId(),
    role,
    username: info.username,
    expiresAt: info.expiresAt || null,
  };
  sessionStorage.setItem(SESSION_KEY, JSON.stringify(session));
 
  await wait(450);
  enterDashboard();
}
 
function getSession() {
  try {
    return JSON.parse(sessionStorage.getItem(SESSION_KEY) || "null");
  } catch {
    return null;
  }
}
 
/* ---------------------------- dashboard ---------------------------- */
 
function enterDashboard() {
  const session = getSession();
  if (!session) return;
 
  document.getElementById("loginScreen").classList.add("hidden");
  const dash = document.getElementById("dashboard");
  dash.classList.remove("hidden");
  document.getElementById("sessionId").textContent = `SESSION ${session.sid}`;
 
  applyClearance(session);
  initDashboard();
}
 
function applyClearance(session) {
  const clearanceLine = document.getElementById("clearanceLine");
  const guestBanner = document.getElementById("guestBanner");
  const guestCard = document.getElementById("guestCard");
  const queryCard = document.getElementById("queryCard");
 
  if (session.role === "ADMIN") {
    clearanceLine.textContent = `CLEARANCE GRANTED · LEVEL 5 · OPERATOR ${session.username}`;
    guestBanner.classList.add("hidden");
    guestCard.classList.remove("hidden");
    queryCard.classList.remove("hidden");
  } else {
    clearanceLine.textContent = `CLEARANCE GRANTED · LEVEL 1 · GUEST ${session.username}`;
    guestBanner.classList.remove("hidden");
    guestCard.classList.add("hidden");
    queryCard.classList.add("hidden");
    startGuestCountdown(session.expiresAt);
  }
}
 
let countdownInterval = null;
 
function startGuestCountdown(expiresAtIso) {
  if (countdownInterval) clearInterval(countdownInterval);
  const el = document.getElementById("guestCountdown");
  const expiresAt = new Date(expiresAtIso).getTime();
 
  function tick() {
    const remainingMs = expiresAt - Date.now();
    if (remainingMs <= 0) {
      el.textContent = "EXPIRED";
      clearInterval(countdownInterval);
      logout();
      return;
    }
    const h = Math.floor(remainingMs / 3600000);
    const m = Math.floor((remainingMs % 3600000) / 60000);
    const s = Math.floor((remainingMs % 60000) / 1000);
    el.textContent = `${pad(h)}H ${pad(m)}M ${pad(s)}S`;
  }
 
  tick();
  countdownInterval = setInterval(tick, 1000);
}
 
function logout() {
  sessionStorage.removeItem(SESSION_KEY);
  if (countdownInterval) clearInterval(countdownInterval);
  setLink("standby");
  document.getElementById("dashboard").classList.add("hidden");
  document.getElementById("loginScreen").classList.remove("hidden");
  document.getElementById("loginForm").reset();
  document.getElementById("feedback").textContent = "";
  document.getElementById("terminalLog").classList.remove("open");
  document.getElementById("terminalLog").innerHTML = "";
  attempts = 0;
  document.getElementById("attemptCounter").textContent = "ATTEMPTS: 0";
  document.getElementById("submitBtn").disabled = false;
}
 
let dashboardInitialized = false;
 
function sysLog(text, cls) {
  const box = document.getElementById("sysLog");
  if (!box) return;
  const line = document.createElement("div");
  const time = new Date();
  line.innerHTML = `<span class="t">${pad(time.getUTCHours())}:${pad(time.getUTCMinutes())}:${pad(time.getUTCSeconds())}</span><span class="${cls || ""}">${escapeHtml(text)}</span>`;
  box.appendChild(line);
  box.scrollTop = box.scrollHeight;
}
 
async function initDashboard() {
  document.getElementById("projUrl").textContent = SUPABASE_URL;
  document.getElementById("projKey").textContent = SUPABASE_PUBLISHABLE_KEY;
 
  if (dashboardInitialized) return;
  dashboardInitialized = true;
 
  sysLog("dev access panel initialized.");
 
  const sb = getSupabase();
  if (!sb) {
    sysLog("supabase-js failed to load from CDN.", "bad");
    setDbStatus(false, "SDK MISSING");
    return;
  }
  sysLog("supabase client created with publishable key.");
 
  try {
    const { error } = await sb.from("__ping__").select("*").limit(1);
    if (error && !/relation .* does not exist/i.test(error.message || "")) {
      throw error;
    }
    setDbStatus(true, "REACHABLE");
    sysLog("project responded to handshake request.", "good");
  } catch (err) {
    setDbStatus(false, "UNREACHABLE");
    sysLog(`handshake failed: ${err.message || err}`, "bad");
  }
 
  const session = getSession();
 
  document.getElementById("runQuery").addEventListener("click", runQuery);
 
  if (session && session.role === "ADMIN") {
    document.getElementById("createGuestBtn").addEventListener("click", createGuestCredential);
    refreshGuestList();
  }
}
 
function setDbStatus(ok, label) {
  const pill = document.getElementById("dbStatus");
  pill.textContent = label;
  pill.className = "pill " + (ok ? "ok" : "bad");
}
 
/* ---------------------------- query console (admin) ---------------------------- */
 
async function runQuery() {
  const sb = getSupabase();
  const table = document.getElementById("tableName").value.trim();
  const limit = Math.min(Math.max(parseInt(document.getElementById("rowLimit").value, 10) || 25, 1), 500);
  const output = document.getElementById("queryOutput");
 
  if (!table) {
    output.innerHTML = '<p class="muted" style="color:var(--alert)">// enter a table name first.</p>';
    return;
  }
  if (!sb) {
    output.innerHTML = '<p class="muted" style="color:var(--alert)">// database client not initialized.</p>';
    return;
  }
 
  output.innerHTML = '<p class="muted">// querying…</p>';
  sysLog(`SELECT * FROM ${table} LIMIT ${limit};`);
 
  const { data, error } = await sb.from(table).select("*").limit(limit);
 
  if (error) {
    output.innerHTML = `<p class="muted" style="color:var(--alert)">// ${escapeHtml(error.message)}</p>`;
    sysLog(`query error: ${error.message}`, "bad");
    return;
  }
 
  if (!data || data.length === 0) {
    output.innerHTML = '<p class="muted">// query succeeded — 0 rows returned.</p>';
    sysLog(`query ok — 0 rows.`, "good");
    return;
  }
 
  sysLog(`query ok — ${data.length} row(s).`, "good");
  output.innerHTML = renderTable(data);
}
 
/* ---------------------------- guest credentials (admin) ---------------------------- */
 
function generateGuestUsername() {
  return `GUEST-${randomHex(2).toUpperCase()}`;
}
 
function generateGuestPassword() {
  // 16 hex chars ≈ 64 bits of entropy — the hash for this is world-readable
  // via the anon key, so the password itself needs to resist offline
  // guessing on its own.
  return randomHex(8);
}
 
async function createGuestCredential() {
  const sb = getSupabase();
  const output = document.getElementById("guestOutput");
  const label = document.getElementById("guestLabel").value.trim();
 
  if (!sb) {
    output.innerHTML = '<p class="muted" style="color:var(--alert)">// database client not initialized.</p>';
    return;
  }
 
  const username = generateGuestUsername();
  const password = generateGuestPassword();
  const passwordHash = await sha256(password);
  const expiresAt = new Date(Date.now() + GUEST_TTL_HOURS * 3600 * 1000).toISOString();
 
  output.innerHTML = '<p class="muted">// issuing credentials…</p>';
 
  const { error } = await sb.from(GUEST_TABLE).insert({
    username,
    password_hash: passwordHash,
    label: label || null,
    expires_at: expiresAt,
  });
 
  if (error) {
    output.innerHTML = `<p class="muted" style="color:var(--alert)">// ${escapeHtml(error.message)} — has guest_access.sql been run in Supabase yet?</p>`;
    sysLog(`guest issue failed: ${error.message}`, "bad");
    return;
  }
 
  sysLog(`guest credential issued: ${username} (expires ${expiresAt}).`, "good");
  document.getElementById("guestLabel").value = "";
 
  output.innerHTML = `
    <p style="color:var(--good); margin:0 0 8px">// credentials generated — shown once, copy them now:</p>
    <div class="kv" style="grid-template-columns:110px 1fr">
      <dt>OPERATOR ID</dt><dd>${escapeHtml(username)}</dd>
      <dt>PASSPHRASE</dt><dd>${escapeHtml(password)}</dd>
      <dt>EXPIRES</dt><dd>${escapeHtml(new Date(expiresAt).toUTCString())}</dd>
    </div>
  `;
 
  refreshGuestList();
}
 
async function refreshGuestList() {
  const sb = getSupabase();
  const box = document.getElementById("guestList");
  if (!sb || !box) return;
 
  const nowIso = new Date().toISOString();
  const { data, error } = await sb
    .from(GUEST_TABLE)
    .select("id, username, label, created_at, expires_at")
    .gt("expires_at", nowIso)
    .order("created_at", { ascending: false });
 
  if (error) {
    box.innerHTML = `<p class="muted" style="color:var(--alert)">// ${escapeHtml(error.message)}</p>`;
    return;
  }
 
  if (!data || data.length === 0) {
    box.innerHTML = '<p class="muted">// no active guest credentials.</p>';
    return;
  }
 
  const rows = data
    .map(
      (g) => `<tr>
        <td>${escapeHtml(g.username)}</td>
        <td>${escapeHtml(g.label || "—")}</td>
        <td>${escapeHtml(new Date(g.expires_at).toUTCString())}</td>
        <td><button class="btn btn--ghost btn--small" data-revoke="${g.id}">REVOKE</button></td>
      </tr>`
    )
    .join("");
 
  box.innerHTML = `
    <table class="result">
      <thead><tr><th>USERNAME</th><th>LABEL</th><th>EXPIRES</th><th></th></tr></thead>
      <tbody>${rows}</tbody>
    </table>
  `;
 
  box.querySelectorAll("[data-revoke]").forEach((btn) => {
    btn.addEventListener("click", () => revokeGuest(btn.getAttribute("data-revoke")));
  });
}
 
async function revokeGuest(id) {
  const sb = getSupabase();
  if (!sb) return;
  const { error } = await sb.from(GUEST_TABLE).delete().eq("id", id);
  if (error) {
    sysLog(`revoke failed: ${error.message}`, "bad");
    return;
  }
  sysLog(`guest credential ${id} revoked.`, "good");
  refreshGuestList();
}
 
/* ---------------------------- shared table renderer ---------------------------- */
 
function renderTable(rows) {
  const cols = Object.keys(rows[0]);
  const thead = `<tr>${cols.map((c) => `<th>${escapeHtml(c)}</th>`).join("")}</tr>`;
  const tbody = rows
    .map(
      (row) =>
        `<tr>${cols.map((c) => `<td>${escapeHtml(formatCell(row[c]))}</td>`).join("")}</tr>`
    )
    .join("");
  return `<table class="result"><thead>${thead}</thead><tbody>${tbody}</tbody></table>`;
}
 
function formatCell(v) {
  if (v === null || v === undefined) return "—";
  if (typeof v === "object") return JSON.stringify(v);
  return String(v);
}
 
/* ---------------------------- boot ---------------------------- */
 
document.addEventListener("DOMContentLoaded", () => {
  tickClock();
  setInterval(tickClock, 1000);
 
  document.getElementById("loginForm").addEventListener("submit", handleLogin);
  document.getElementById("logoutBtn").addEventListener("click", logout);
 
  const session = getSession();
  if (session) {
    if (session.role === "GUEST" && session.expiresAt && new Date(session.expiresAt).getTime() <= Date.now()) {
      sessionStorage.removeItem(SESSION_KEY);
    } else {
      setLink("live");
      enterDashboard();
    }
  }
});
