/* =========================================================================
   SECTOR-9 SHARED UTILITIES
   -------------------------------------------------------------------------
   Loaded on every page (index.html + forum.html). Holds:
     - the two Supabase client factories (main project + forum project)
     - session read/write helpers (sessionStorage-backed)
     - small crypto / formatting utilities used across pages

   IMPORTANT — read this even though the UI says "TOP SECRET":
   This is a STATIC site (GitHub Pages). There is no server to keep a
   secret from a determined visitor. Anyone can open dev tools and read
   the keys below, and — because there's no real backend — anyone
   holding the Supabase publishable key (which is public the moment this
   site is live) can call the same Supabase tables directly, bypassing
   these pages entirely, UNLESS you lock the tables down with real RLS
   policies. Treat the login screen as theming and a speed bump, not a
   security boundary.
   ========================================================================= */

const SUPABASE_URL = "https://vnhgnrxixwudicwqqqzu.supabase.co";
const SUPABASE_PUBLISHABLE_KEY = "sb_publishable_1QouxYIS9jrupTIWtBeG2A_RxyPawXE";

const GUEST_TABLE = "guest_access";
const GUEST_TTL_HOURS = 24;
const LOGIN_LOG_TABLE = "login_attempts";
const DEV_PROFILES_TABLE = "dev_profiles";
const BANNER_MESSAGES_TABLE = "banner_messages";

const SESSION_KEY = "sector9_session";

/* ---------------------------- forum (separate Supabase project) ----------------------------
   The forum lives in its own Supabase project (kept separate from the auth/admin project
   above on purpose). It only becomes reachable once a session exists in sessionStorage,
   and every post is written under session.username — there is no independent forum login. */
const FORUM_SUPABASE_URL = "https://jvrmohmrutoprovqtozv.supabase.co";
const FORUM_SUPABASE_KEY = "sb_publishable_tbIHdpgjxmQ1C9e2ZAjeEA__1-esu8G";
const FORUM_CHANNELS_TABLE = "forum_channels";
const FORUM_POSTS_TABLE = "forum_posts";
const FORUM_ADMIN_USERNAME = "JEGM";

/* ---------------------------- crypto / formatting utilities ---------------------------- */

async function sha256(text) {
  const enc = new TextEncoder().encode(text);
  const digest = await crypto.subtle.digest("SHA-256", enc);
  return Array.from(new Uint8Array(digest))
    .map((b) => b.toString(16).padStart(2, "0"))
    .join("");
}

function pad(n) { return n.toString().padStart(2, "0"); }

function wait(ms) { return new Promise((r) => setTimeout(r, ms)); }

function randomHex(byteLen) {
  return Array.from(crypto.getRandomValues(new Uint8Array(byteLen)))
    .map((b) => b.toString(16).padStart(2, "0"))
    .join("");
}

function randomSessionId() {
  return randomHex(4).toUpperCase();
}

function escapeHtml(str) {
  return String(str)
    .replace(/&/g, "&amp;")
    .replace(/</g, "&lt;")
    .replace(/>/g, "&gt;")
    .replace(/"/g, "&quot;");
}

/* ---------------------------- clock / uplink indicator ---------------------------- */

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

function bootClock() {
  tickClock();
  setInterval(tickClock, 1000);
}

/* ---------------------------- supabase clients ---------------------------- */

function getSupabase() {
  if (window.__sb) return window.__sb;
  if (typeof window.supabase === "undefined") return null;
  window.__sb = window.supabase.createClient(SUPABASE_URL, SUPABASE_PUBLISHABLE_KEY);
  return window.__sb;
}

function getForumSupabase() {
  if (window.__fsb) return window.__fsb;
  if (typeof window.supabase === "undefined") return null;
  window.__fsb = window.supabase.createClient(FORUM_SUPABASE_URL, FORUM_SUPABASE_KEY);
  return window.__fsb;
}

/* ---------------------------- session ---------------------------- */

function getSession() {
  try {
    return JSON.parse(sessionStorage.getItem(SESSION_KEY) || "null");
  } catch {
    return null;
  }
}

function setSession(session) {
  sessionStorage.setItem(SESSION_KEY, JSON.stringify(session));
}

function clearSession() {
  sessionStorage.removeItem(SESSION_KEY);
}

/* A session is valid if it exists and, for GUEST roles, hasn't expired yet. */
function getValidSession() {
  const session = getSession();
  if (!session) return null;
  if (session.role === "GUEST" && session.expiresAt && new Date(session.expiresAt).getTime() <= Date.now()) {
    clearSession();
    return null;
  }
  return session;
}

function isForumAdmin(session) {
  return !!session && session.role === "ADMIN";
}
