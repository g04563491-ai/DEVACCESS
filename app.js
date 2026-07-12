cat > /home/claude/site/app.js << 'EOF'
/* =========================================================================
   SECTOR-9 ACCESS TERMINAL
   -------------------------------------------------------------------------
   Credentials are never stored in plaintext. Only a SHA-256 digest of the
   admin operator ID and passphrase live in this file. Guest and permanent
   profile credentials work the same way, but their digests live in
   Supabase tables instead of hardcoded here.

   IMPORTANT — read this even though the UI says "TOP SECRET":
   This is a STATIC site (GitHub Pages). There is no server to keep a
   secret from a determined visitor, and no server to enforce the IP-ban /
   attempt-logging logic below either — it all runs in the visitor's own
   browser and writes to Supabase using the public publishable key. That
   means:
     - the admin digest is readable in this file,
     - the "IP" used for banning is self-reported by the browser (fetched
       from a third-party lookup service) and can be spoofed or simply
       skipped by anyone calling the Supabase table directly instead of
       using this page,
     - someone behind a shared IP (office, campus, CGNAT mobile network)
       can be banned by someone else's failed attempts, and a VPN trivially
       evades a ban.
   This is still useful as a deterrent against casual/automated guessing
   through the actual page, and as an audit trail — just don't treat it as
   a hard security boundary. See guest_access.sql and profiles_and_security.sql
   for the same caveat applied to the database policies.
   ========================================================================= */

const EXPECTED_USER_HASH = "5fa4174c6f614af6121eb0d90ef3f78c3f3758c122b97dac823cb232e8e8b203";
const EXPECTED_PASS_HASH = "c73c7ba95a20de28d8b972c40ef32a8a03f5cd9a859ae8c8da56e9ee9da23aac";

const SUPABASE_URL = "https://vnhgnrxixwudicwqqqzu.supabase.co";
const SUPABASE_PUBLISHABLE_KEY = "sb_publishable_1QouxYIS9jrupTIWtBeG2A_RxyPawXE";

const GUEST_TABLE = "guest_access";
const GUEST_TTL_HOURS = 24;

const FAIL_THRESHOLD = 5;      // failed attempts from one IP...
const FAIL_WINDOW_HOURS = 24;  // ...within this many hours...
const BAN_HOURS = 24;          // ...triggers a ban lasting this long.

const PERMISSIONS = [
  { key: "query_console", label: "Query Console" },
  { key: "issue_guests", label: "Issue Guest Credentials" },
];

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

function formatRemaining(ms) {
  if (ms <= 0) return "0H 0M";
  const h = Math.floor(ms / 3600000);
  const m = Math.floor((ms % 3600000) / 60000);
  return `${h}H ${m}M`;
}

function hasPermission(session, key) {
  if (!session) return false;
  if (session.role === "ADMIN") return true;
  return Array.isArray(session.permissions) && session.permissions.includes(key);
}

/* ---------------------------- client IP (self-reported) ---------------------------- */

let cachedIp = null;

async function getClientIp() {
  if (cachedIp) return cachedIp;
  try {
    const res = await fetch("https://api.ipify.org?format=json");
    const data = await res.json();
    cachedIp = data.ip || "unknown";
  } catch {
    cachedIp = "unknown";
  }
  return cachedIp;
}

/* ---------------------------- login attempt logging / bans ---------------------------- */

async function logAttempt(username, ip, success) {
  const sb = getSupabase();
  if (!sb) return;
  try {
    await sb.from("login_attempts").insert({ username: username || null, ip: ip || "unknown", success });
  } catch {
    /* best-effort — a logging failure should never block login itself */
  }
}

async function getActiveBan(ip) {
  const sb = getSupabase();
  if (!sb || !ip || ip === "unknown") return null;
  const nowIso = new Date().toISOString();
  const { data } = await sb
    .from("ip_bans")
    .select("banned_until")
    .eq("ip", ip)
    .gt("banned_until", nowIso)
    .maybeSingle();
  return data;
}

async function maybeBanIp(ip) {
  const sb = getSupabase();
  if (!sb || !ip || ip === "unknown") return false;

  const since = new Date(Date.now() - FAIL_WINDOW_HOURS * 3600 * 1000).toISOString();
  const { count, error } = await sb
    .from("login_attempts")
    .select("id", { count: "exact", head: true })
    .eq("ip", ip)
    .eq("success", false)
    .gt("created_at", since);

  if (error) return false;

  if ((count || 0) >= FAIL_THRESHOLD) {
    const bannedUntil = new Date(Date.now() + BAN_HOURS * 3600 * 1000).toISOString();
    await sb.from("ip_bans").upsert({
      ip,
      banned_until: bannedUntil,
      reason: `${FAIL_THRESHOLD} failed login attempts within ${FAIL_WINDOW_HOURS}h`,
    });
    return true;
  }
  return false;
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

  submitBtn.disabled = true;
  feedback.textContent = "";
  feedback.className = "feedback";
  log.classList.add("open");
  log.innerHTML = "";

  logLine(log, "> resolving origin address…", "accent");
  const ip = await getClientIp();
  logLine(log, `> origin: ${ip}`);

  const ban = await getActiveBan(ip);
  if (ban) {
    const remaining = formatRemaining(new Date(ban.banned_until).getTime() - Date.now());
    logLine(log, "> origin is on the ban list — request refused.", "bad");
    feedback.textContent = `ACCESS DENIED — IP BANNED (${remaining} REMAINING)`;
    submitBtn.disabled = false;
    return;
  }

  attempts += 1;
  document.getElementById("attemptCounter").textContent = `ATTEMPTS: ${attempts}`;

  logLine(log, "> hashing operator id (SHA-256)…");
  const userHash = await sha256(userInput);
  logLine(log, "> hashing passphrase (SHA-256)…");
  const passHash = await sha256(passInput);
  logLine(log, "> comparing digests against clearance ledger…");
  await wait(260);

  if (userHash === EXPECTED_USER_HASH && passHash === EXPECTED_PASS_HASH) {
    await logAttempt(userInput, ip, true);
    return grantAccess(log, feedback, "ADMIN", { username: userInput, permissions: [] });
  }

  logLine(log, "> no local match — checking guest ledger…");
  const guest = await checkGuestCredential(userInput, passHash);
  if (guest) {
    await logAttempt(userInput, ip, true);
    return grantAccess(log, feedback, "GUEST", {
      username: userInput,
      expiresAt: guest.expires_at,
      permissions: [],
    });
  }

  logLine(log, "> checking permanent profiles…");
  const profile = await checkCustomProfile(userInput, passHash);
  if (profile) {
    await logAttempt(userInput, ip, true);
    return grantAccess(log, feedback, "CUSTOM", {
      username: userInput,
      permissions: profile.permissions || [],
    });
  }

  logLine(log, "> digest mismatch — credentials rejected.", "bad");
  await logAttempt(userInput, ip, false);
  const justBanned = await maybeBanIp(ip);

  if (justBanned) {
    logLine(log, `> ${FAIL_THRESHOLD} failed attempts from ${ip} — origin banned for ${BAN_HOURS}h.`, "bad");
    feedback.textContent = `ACCESS DENIED — TOO MANY FAILURES, IP BANNED ${BAN_HOURS}H`;
  } else {
    logLine(log, `> incident logged: attempt #${attempts} from this terminal.`, "bad");
    feedback.textContent = "ACCESS DENIED — CREDENTIALS INVALID";
  }
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

async function checkCustomProfile(username, passHash) {
  const sb = getSupabase();
  if (!sb || !username) return null;

  const { data, error } = await sb
    .from("custom_profiles")
    .select("username, password_hash, permissions")
    .eq("username", username)
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
    permissions: info.permissions || [],
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
  const levels = { ADMIN: 5, CUSTOM: 3, GUEST: 1 };

  clearanceLine.textContent =
    `CLEARANCE GRANTED · LEVEL ${levels[session.role] || 1} · ${session.role} ${session.username}`;

  document.querySelectorAll(".admin-only").forEach((el) => {
    el.classList.toggle("hidden", session.role !== "ADMIN");
  });

  guestCard.classList.toggle("hidden", !hasPermission(session, "issue_guests"));
  queryCard.classList.toggle("hidden", !hasPermission(session, "query_console"));

  if (session.role === "GUEST") {
    guestBanner.classList.remove("hidden");
    startGuestCountdown(session.expiresAt);
  } else {
    guestBanner.classList.add("hidden");
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

let broadcastPollInterval = null;
let dashboardInitialized = false;

function logout() {
  sessionStorage.removeItem(SESSION_KEY);
  if (countdownInterval) clearInterval(countdownInterval);
  if (broadcastPollInterval) { clearInterval(broadcastPollInterval); broadcastPollInterval = null; }
  dashboardInitialized = false;

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

  loadBroadcastBanners();
  if (!broadcastPollInterval) {
    broadcastPollInterval = setInterval(loadBroadcastBanners, 30000);
  }

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

  if (hasPermission(session, "query_console")) {
    document.getElementById("runQuery").addEventListener("click", runQuery);
  }
  if (hasPermission(session, "issue_guests")) {
    document.getElementById("createGuestBtn").addEventListener("click", createGuestCredential);
    refreshGuestList();
  }

  if (session && session.role === "ADMIN") {
    renderPermCheckboxes();
    document.getElementById("createProfileBtn").addEventListener("click", createProfile);
    refreshProfileList();

    document.getElementById("sendBroadcastBtn").addEventListener("click", sendBroadcast);
    refreshBroadcastList();

    refreshActivity();
  }
}

function setDbStatus(ok, label) {
  const pill = document.getElementById("dbStatus");
  pill.textContent = label;
  pill.className = "pill " + (ok ? "ok" : "bad");
}

/* ---------------------------- query console ---------------------------- */

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

/* ---------------------------- guest credentials ---------------------------- */

function generateGuestUsername() {
  return `GUEST-${randomHex(2).toUpperCase()}`;
}

function generateGuestPassword() {
  return randomHex(8); // 16 hex chars ≈ 64 bits — the hash is world-readable, so entropy matters
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

/* ---------------------------- permanent profiles + permissions (admin) ---------------------------- */

function renderPermCheckboxes() {
  const row = document.getElementById("createPermRow");
  row.innerHTML = PERMISSIONS.map(
    (p) => `<label class="perm-check"><input type="checkbox" value="${p.key}" /> ${escapeHtml(p.label)}</label>`
  ).join("");
}

async function createProfile() {
  const sb = getSupabase();
  const output = document.getElementById("profileOutput");
  const username = document.getElementById("profileUsername").value.trim();
  const password = document.getElementById("profilePassword").value;
  const label = document.getElementById("profileLabel").value.trim();
  const perms = Array.from(document.querySelectorAll("#createPermRow input:checked")).map((i) => i.value);

  if (!username || !password) {
    output.innerHTML = '<p class="muted" style="color:var(--alert)">// username and password are required.</p>';
    return;
  }
  if (!sb) {
    output.innerHTML = '<p class="muted" style="color:var(--alert)">// database client not initialized.</p>';
    return;
  }

  const passwordHash = await sha256(password);
  output.innerHTML = '<p class="muted">// creating profile…</p>';

  const { error } = await sb.from("custom_profiles").insert({
    username,
    password_hash: passwordHash,
    permissions: perms,
    label: label || null,
  });

  if (error) {
    output.innerHTML = `<p class="muted" style="color:var(--alert)">// ${escapeHtml(error.message)} — has profiles_and_security.sql been run yet?</p>`;
    sysLog(`profile create failed: ${error.message}`, "bad");
    return;
  }

  sysLog(`permanent profile created: ${username}.`, "good");
  output.innerHTML = '<p style="color:var(--good)">// profile created — share the username/password with them directly, it will not be shown again.</p>';
  document.getElementById("profileUsername").value = "";
  document.getElementById("profilePassword").value = "";
  document.getElementById("profileLabel").value = "";
  document.querySelectorAll("#createPermRow input").forEach((i) => (i.checked = false));

  refreshProfileList();
}

async function refreshProfileList() {
  const sb = getSupabase();
  const box = document.getElementById("profileList");
  if (!sb) return;

  const { data, error } = await sb
    .from("custom_profiles")
    .select("id, username, label, permissions, created_at")
    .order("created_at", { ascending: false });

  if (error) {
    box.innerHTML = `<p class="muted" style="color:var(--alert)">// ${escapeHtml(error.message)}</p>`;
    return;
  }
  if (!data || data.length === 0) {
    box.innerHTML = '<p class="muted">// no permanent profiles yet.</p>';
    return;
  }

  box.innerHTML = data
    .map(
      (p) => `
    <div class="profile-row" data-id="${p.id}">
      <span class="profile-row__name">${escapeHtml(p.username)}${p.label ? ` <span class="muted">(${escapeHtml(p.label)})</span>` : ""}</span>
      <span class="profile-row__perms">
        ${PERMISSIONS.map(
          (perm) => `
          <label class="perm-check">
            <input type="checkbox" data-perm="${perm.key}" ${p.permissions?.includes(perm.key) ? "checked" : ""} />
            ${escapeHtml(perm.label)}
          </label>`
        ).join("")}
      </span>
      <button class="btn btn--ghost btn--small" data-revoke-profile="${p.id}">REVOKE</button>
    </div>`
    )
    .join("");

  box.querySelectorAll(".profile-row").forEach((row) => {
    const id = row.getAttribute("data-id");
    row.querySelectorAll("input[data-perm]").forEach((cb) => {
      cb.addEventListener("change", () => updateProfilePermissions(id, row));
    });
  });
  box.querySelectorAll("[data-revoke-profile]").forEach((btn) => {
    btn.addEventListener("click", () => revokeProfile(btn.getAttribute("data-revoke-profile")));
  });
}

async function updateProfilePermissions(id, row) {
  const sb = getSupabase();
  const perms = Array.from(row.querySelectorAll("input[data-perm]:checked")).map((i) => i.getAttribute("data-perm"));
  const { error } = await sb.from("custom_profiles").update({ permissions: perms }).eq("id", id);
  if (error) {
    sysLog(`permission update failed: ${error.message}`, "bad");
    return;
  }
  sysLog(`permissions updated for profile ${id}.`, "good");
}

async function revokeProfile(id) {
  const sb = getSupabase();
  const { error } = await sb.from("custom_profiles").delete().eq("id", id);
  if (error) {
    sysLog(`profile revoke failed: ${error.message}`, "bad");
    return;
  }
  sysLog(`profile ${id} revoked.`, "good");
  refreshProfileList();
}

/* ---------------------------- broadcast messages ---------------------------- */

async function sendBroadcast() {
  const sb = getSupabase();
  const input = document.getElementById("broadcastText");
  const text = input.value.trim();
  if (!text || !sb) return;

  const { error } = await sb.from("messages").insert({ body: text, active: true });
  if (error) {
    sysLog(`broadcast failed: ${error.message}`, "bad");
    return;
  }
  sysLog(`broadcast sent: "${text}"`, "good");
  input.value = "";
  refreshBroadcastList();
  loadBroadcastBanners();
}

async function refreshBroadcastList() {
  const sb = getSupabase();
  const box = document.getElementById("broadcastList");
  if (!sb) return;

  const { data, error } = await sb
    .from("messages")
    .select("id, body, created_at")
    .eq("active", true)
    .order("created_at", { ascending: false });

  if (error) {
    box.innerHTML = `<p class="muted" style="color:var(--alert)">// ${escapeHtml(error.message)} — has profiles_and_security.sql been run yet?</p>`;
    return;
  }
  if (!data || data.length === 0) {
    box.innerHTML = '<p class="muted">// no active broadcasts.</p>';
    return;
  }

  box.innerHTML = data
    .map(
      (m) => `
    <div class="profile-row" data-id="${m.id}">
      <span style="flex:1">${escapeHtml(m.body)}</span>
      <button class="btn btn--ghost btn--small" data-retract="${m.id}">RETRACT</button>
    </div>`
    )
    .join("");

  box.querySelectorAll("[data-retract]").forEach((btn) => {
    btn.addEventListener("click", () => retractBroadcast(btn.getAttribute("data-retract")));
  });
}

async function retractBroadcast(id) {
  const sb = getSupabase();
  const { error } = await sb.from("messages").update({ active: false }).eq("id", id);
  if (error) {
    sysLog(`retract failed: ${error.message}`, "bad");
    return;
  }
  sysLog(`broadcast ${id} retracted.`, "good");
  refreshBroadcastList();
  loadBroadcastBanners();
}

async function loadBroadcastBanners() {
  const sb = getSupabase();
  const box = document.getElementById("broadcastBanners");
  if (!sb || !box) return;

  const { data, error } = await sb
    .from("messages")
    .select("id, body, created_at")
    .eq("active", true)
    .order("created_at", { ascending: false })
    .limit(5);

  if (error || !data || data.length === 0) {
    box.innerHTML = "";
    return;
  }

  box.innerHTML = data
    .map(
      (m) => `
    <div class="msg-banner">
      <span>${escapeHtml(m.body)}</span>
      <span class="msg-banner__time">${escapeHtml(new Date(m.created_at).toUTCString())}</span>
    </div>`
    )
    .join("");
}

/* ---------------------------- login activity + bans (admin) ---------------------------- */

async function refreshActivity() {
  const sb = getSupabase();
  const banBox = document.getElementById("banList");
  const attemptBox = document.getElementById("attemptList");
  if (!sb) return;

  const nowIso = new Date().toISOString();
  const { data: bans, error: banErr } = await sb
    .from("ip_bans")
    .select("ip, banned_until, reason")
    .gt("banned_until", nowIso)
    .order("banned_until", { ascending: false });

  if (banErr) {
    banBox.innerHTML = `<p class="muted" style="color:var(--alert)">// ${escapeHtml(banErr.message)} — has profiles_and_security.sql been run yet?</p>`;
  } else if (!bans || bans.length === 0) {
    banBox.innerHTML = '<p class="muted">// no active bans.</p>';
  } else {
    banBox.innerHTML = bans
      .map(
        (b) => `
      <div class="profile-row">
        <span class="profile-row__name">${escapeHtml(b.ip)}</span>
        <span class="muted" style="flex:1">until ${escapeHtml(new Date(b.banned_until).toUTCString())}</span>
        <button class="btn btn--ghost btn--small" data-unban="${escapeHtml(b.ip)}">UNBAN</button>
      </div>`
      )
      .join("");
    banBox.querySelectorAll("[data-unban]").forEach((btn) => {
      btn.addEventListener("click", () => unbanIp(btn.getAttribute("data-unban")));
    });
  }

  const { data: recent, error: attErr } = await sb
    .from("login_attempts")
    .select("username, ip, success, created_at")
    .order("created_at", { ascending: false })
    .limit(25);

  if (attErr) {
    attemptBox.innerHTML = `<p class="muted" style="color:var(--alert)">// ${escapeHtml(attErr.message)}</p>`;
    return;
  }
  if (!recent || recent.length === 0) {
    attemptBox.innerHTML = '<p class="muted">// no login attempts logged yet.</p>';
    return;
  }

  attemptBox.innerHTML = renderTable(
    recent.map((a) => ({
      time: new Date(a.created_at).toUTCString(),
      username: a.username || "—",
      ip: a.ip || "—",
      result: a.success ? "OK" : "FAILED",
    }))
  );
}

async function unbanIp(ip) {
  const sb = getSupabase();
  const { error } = await sb.from("ip_bans").delete().eq("ip", ip);
  if (error) {
    sysLog(`unban failed: ${error.message}`, "bad");
    return;
  }
  sysLog(`${ip} unbanned.`, "good");
  refreshActivity();
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
