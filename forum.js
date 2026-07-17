/* =========================================================================
   SECTOR-9 FORUM
   -------------------------------------------------------------------------
   Standalone forum page. Requires a valid session created by index.html
   (sessionStorage-backed — see shared.js). There is no separate forum
   login: posts are written under session.username. Only @JEGM (ADMIN
   role) can create new channels.

   Forum data lives in its own Supabase project, kept separate from the
   auth/admin project on purpose (see shared.js for both client configs).
   ========================================================================= */

const forumState = {
  channels: [],
  activeChannelId: null,
  session: null,
};

function forumSysLog(text, cls) {
  const box = document.getElementById("forumSysLog");
  if (!box) return;
  const line = document.createElement("div");
  const time = new Date();
  line.innerHTML = `<span class="t">${pad(time.getUTCHours())}:${pad(time.getUTCMinutes())}:${pad(time.getUTCSeconds())}</span><span class="${cls || ""}">${escapeHtml(text)}</span>`;
  box.appendChild(line);
  box.scrollTop = box.scrollHeight;
}

/* ---------------------------- gate / boot ---------------------------- */

function showGate() {
  document.getElementById("forumGate").classList.remove("hidden");
  document.getElementById("forumApp").classList.add("hidden");
}

function reportFatalError(err) {
  const message = err && err.message ? err.message : String(err);
  console.error("forum fatal error:", err);
  const box = document.getElementById("forumSysLog");
  if (box) {
    forumSysLog(`fatal error: ${message}`, "bad");
  } else {
    // Boot failed before the app view even rendered — fall back to an alert
    // so this is never silent, since there's nowhere on-page to log it.
    document.title = "SECTOR-9 :: FORUM (ERROR)";
  }
}

function showForum(session) {
  try {
    document.getElementById("forumGate").classList.add("hidden");
    document.getElementById("forumApp").classList.remove("hidden");

    document.getElementById("sessionId").textContent = `SESSION ${session.sid}`;

    const roleLabel =
      session.role === "ADMIN" ? "LEVEL 5 · OPERATOR" :
      session.role === "DEV" ? `LEVEL 3 · DEV [${session.devRole}]` :
      "LEVEL 1 · GUEST";
    document.getElementById("forumClearanceLine").textContent = `CLEARANCE GRANTED · ${roleLabel} ${session.username}`;

    const guestBanner = document.getElementById("forumGuestBanner");
    if (session.role === "GUEST") {
      guestBanner.classList.remove("hidden");
      startForumGuestCountdown(session.expiresAt);
    } else {
      guestBanner.classList.add("hidden");
    }

    if (typeof window.supabase === "undefined") {
      forumSysLog("supabase-js failed to load from CDN — check network/ad-blockers.", "bad");
      document.getElementById("forumChannelList").innerHTML =
        '<p class="muted" style="color:var(--alert)">// forum database client not initialized.</p>';
      return;
    }

    initForum(session);
  } catch (err) {
    reportFatalError(err);
  }
}

let forumCountdownInterval = null;

function startForumGuestCountdown(expiresAtIso) {
  if (forumCountdownInterval) clearInterval(forumCountdownInterval);
  const el = document.getElementById("forumGuestCountdown");
  const expiresAt = new Date(expiresAtIso).getTime();

  function tick() {
    const remainingMs = expiresAt - Date.now();
    if (remainingMs <= 0) {
      el.textContent = "EXPIRED";
      clearInterval(forumCountdownInterval);
      handleLogout();
      return;
    }
    const h = Math.floor(remainingMs / 3600000);
    const m = Math.floor((remainingMs % 3600000) / 60000);
    const s = Math.floor((remainingMs % 60000) / 1000);
    el.textContent = `${pad(h)}H ${pad(m)}M ${pad(s)}S`;
  }

  tick();
  forumCountdownInterval = setInterval(tick, 1000);
}

function handleLogout() {
  clearSession();
  if (forumCountdownInterval) clearInterval(forumCountdownInterval);
  window.location.href = "index.html";
}

/* ---------------------------- forum ---------------------------- */

function initForum(session) {
  forumState.session = session;

  const userPill = document.getElementById("forumUserPill");
  if (userPill) userPill.textContent = `POSTING AS ${session.username}`;

  const addRow = document.getElementById("forumAddChannelRow");
  if (addRow) addRow.style.display = isForumAdmin(session) ? "flex" : "none";

  document.getElementById("forumCreateChannelBtn")?.addEventListener("click", () => createForumChannel(forumState.session));
  document.getElementById("forumPostBtn")?.addEventListener("click", () => submitForumPost(forumState.session));

  document.getElementById("forumPostText")?.addEventListener("keydown", (e) => {
    if (e.key === "Enter" && (e.metaKey || e.ctrlKey)) {
      e.preventDefault();
      submitForumPost(forumState.session);
    }
  });

  forumSysLog("forum session established.");
  loadForumChannels(session);
}

async function loadForumChannels(session) {
  const sb = getForumSupabase();
  const list = document.getElementById("forumChannelList");
  if (!list) return;

  if (!sb) {
    list.innerHTML = '<p class="muted" style="color:var(--alert)">// forum database client not initialized.</p>';
    forumSysLog("supabase-js failed to load from CDN.", "bad");
    return;
  }

  let data, error;
  try {
    ({ data, error } = await sb
      .from(FORUM_CHANNELS_TABLE)
      .select("id, name, description")
      .order("name", { ascending: true }));
  } catch (err) {
    list.innerHTML = `<p class="muted" style="color:var(--alert)">// request failed: ${escapeHtml(err.message || String(err))}</p>`;
    forumSysLog(`channel load threw: ${err.message || err}`, "bad");
    return;
  }

  if (error) {
    list.innerHTML = `<p class="muted" style="color:var(--alert)">// ${escapeHtml(error.message)}</p>`;
    forumSysLog(`channel load failed: ${error.message}`, "bad");
    return;
  }

  forumState.channels = data || [];

  if (forumState.channels.length === 0) {
    list.innerHTML = '<p class="muted">// no channels yet.</p>';
    document.getElementById("forumPosts").innerHTML = '<p class="muted">// no channel selected.</p>';
    return;
  }

  if (!forumState.activeChannelId || !forumState.channels.some((c) => c.id === forumState.activeChannelId)) {
    forumState.activeChannelId = forumState.channels[0].id;
  }

  list.innerHTML = forumState.channels
    .map(
      (c) => `<button type="button" class="forum-channel-btn${c.id === forumState.activeChannelId ? " active" : ""}" data-channel="${c.id}" title="${escapeHtml(c.description || "")}">
        #${escapeHtml(c.name)}
      </button>`
    )
    .join("");

  list.querySelectorAll("[data-channel]").forEach((btn) => {
    btn.addEventListener("click", () => selectForumChannel(session, Number(btn.getAttribute("data-channel"))));
  });

  updateActiveChannelHeading();
  loadForumPosts(forumState.activeChannelId);
}

function updateActiveChannelHeading() {
  const heading = document.getElementById("forumActiveChannel");
  if (!heading) return;
  const active = forumState.channels.find((c) => c.id === forumState.activeChannelId);
  heading.textContent = active ? `#${active.name}` : "—";
}

function selectForumChannel(session, channelId) {
  forumState.activeChannelId = channelId;
  document.querySelectorAll(".forum-channel-btn").forEach((btn) => {
    btn.classList.toggle("active", Number(btn.getAttribute("data-channel")) === channelId);
  });
  updateActiveChannelHeading();
  loadForumPosts(channelId);
}

async function loadForumPosts(channelId) {
  const sb = getForumSupabase();
  const box = document.getElementById("forumPosts");
  if (!sb || !box || !channelId) return;

  box.innerHTML = '<p class="muted">// loading posts…</p>';

  let data, error;
  try {
    ({ data, error } = await sb
      .from(FORUM_POSTS_TABLE)
      .select("id, username, content, created_at")
      .eq("channel_id", channelId)
      .order("created_at", { ascending: true }));
  } catch (err) {
    box.innerHTML = `<p class="muted" style="color:var(--alert)">// request failed: ${escapeHtml(err.message || String(err))}</p>`;
    forumSysLog(`post load threw: ${err.message || err}`, "bad");
    return;
  }

  if (error) {
    box.innerHTML = `<p class="muted" style="color:var(--alert)">// ${escapeHtml(error.message)}</p>`;
    forumSysLog(`post load failed: ${error.message}`, "bad");
    return;
  }

  if (!data || data.length === 0) {
    box.innerHTML = '<p class="muted">// no posts in this channel yet — be the first.</p>';
    return;
  }

  box.innerHTML = data
    .map(
      (p) => `<div class="forum-post">
        <div class="forum-post__meta"><span class="forum-post__user">${escapeHtml(p.username)}</span><span class="forum-post__time">${escapeHtml(new Date(p.created_at).toUTCString())}</span></div>
        <div class="forum-post__body">${escapeHtml(p.content)}</div>
      </div>`
    )
    .join("");

  box.scrollTop = box.scrollHeight;
}

async function submitForumPost(session) {
  const sb = getForumSupabase();
  const textarea = document.getElementById("forumPostText");
  const content = textarea?.value.trim();

  if (!sb) return;
  if (!forumState.activeChannelId) {
    forumSysLog("forum post failed: no channel selected.", "bad");
    return;
  }
  if (!content) return;

  const { error } = await sb.from(FORUM_POSTS_TABLE).insert({
    channel_id: forumState.activeChannelId,
    username: session.username,
    content,
  });

  if (error) {
    forumSysLog(`forum post failed: ${error.message}`, "bad");
    return;
  }

  textarea.value = "";
  loadForumPosts(forumState.activeChannelId);
}

async function createForumChannel(session) {
  if (!isForumAdmin(session)) return;

  const sb = getForumSupabase();
  const nameInput = document.getElementById("forumChannelName");
  const descInput = document.getElementById("forumChannelDesc");
  const name = nameInput?.value.trim().toLowerCase().replace(/\s+/g, "-");
  const description = descInput?.value.trim() || null;

  if (!sb || !name) return;

  const { error } = await sb.from(FORUM_CHANNELS_TABLE).insert({
    name,
    description,
    created_by: session.username,
  });

  if (error) {
    forumSysLog(`channel creation failed: ${error.message}`, "bad");
    return;
  }

  forumSysLog(`forum channel #${name} created.`, "good");
  nameInput.value = "";
  descInput.value = "";
  loadForumChannels(session);
}

/* ---------------------------- boot ---------------------------- */

document.addEventListener("DOMContentLoaded", () => {
  try {
    bootClock();

    document.getElementById("forumLogoutBtn")?.addEventListener("click", handleLogout);

    const session = getValidSession();
    if (!session) {
      setLink("standby");
      showGate();
      return;
    }

    setLink("live");
    showForum(session);
  } catch (err) {
    reportFatalError(err);
  }
});
