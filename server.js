// -----------------------------------------------------------------
//  Reservation SMS Confirmation Server — Multi-Tenant
//  Express + Twilio, Postgres-backed, row-level isolation by franchise_id.
// -----------------------------------------------------------------

require("dotenv").config();
const express = require("express");
const cors = require("cors");
const twilio = require("twilio");
const helmet = require("helmet");
const rateLimit = require("express-rate-limit");
const session = require("express-session");
const crypto = require("crypto");
const path = require("path");
const { OAuth2Client } = require("google-auth-library");
const webpush = require("web-push");
const db = require("./db");
const { classifyIntent } = require("./lib/intent");

// --- Web Push (PWA notifications) ---
const VAPID_PUBLIC_KEY = process.env.VAPID_PUBLIC_KEY || "";
const VAPID_PRIVATE_KEY = process.env.VAPID_PRIVATE_KEY || "";
const VAPID_SUBJECT = process.env.VAPID_SUBJECT || "mailto:admin@example.com";
const pushEnabled = !!(VAPID_PUBLIC_KEY && VAPID_PRIVATE_KEY);
if (pushEnabled) {
  webpush.setVapidDetails(VAPID_SUBJECT, VAPID_PUBLIC_KEY, VAPID_PRIVATE_KEY);
} else {
  console.warn("Web Push disabled — VAPID_PUBLIC_KEY / VAPID_PRIVATE_KEY not set.");
}

// Fan out a payload to every relevant subscriber for an inbound SMS:
//   - admins (super_admin / franchise_admin) for the franchise — always
//   - franchise_staff users only if their dock_id matches `dockId`
//   - franchise_staff users with NULL dock_id (legacy, un-scoped) — always
// Passing dockId=null is the "orphan inbound" case (no reservation matched);
// only admins receive that. Dead/expired subscriptions (404/410) are pruned.
async function pushForInbound(franchiseId, dockId, payload) {
  if (!pushEnabled || !franchiseId) return;
  const { rows } = await db.query(
    `SELECT ps.id, ps.endpoint, ps.p256dh, ps.auth
       FROM push_subscriptions ps
       JOIN users u ON u.id = ps.user_id
      WHERE ps.franchise_id = $1
        AND (
          u.role IN ('super_admin', 'franchise_admin')
          OR (u.role = 'franchise_staff' AND ($2::text IS NOT NULL) AND (u.dock_id = $2 OR u.dock_id IS NULL))
        )`,
    [franchiseId, dockId || null]
  );
  if (rows.length === 0) return;
  const body = JSON.stringify(payload);
  const stale = [];
  await Promise.all(rows.map(async (sub) => {
    try {
      await webpush.sendNotification(
        { endpoint: sub.endpoint, keys: { p256dh: sub.p256dh, auth: sub.auth } },
        body
      );
    } catch (err) {
      if (err && (err.statusCode === 404 || err.statusCode === 410)) {
        stale.push(sub.id);
      } else {
        console.error("Push send error:", err && err.message);
      }
    }
  }));
  if (stale.length > 0) {
    await db.query(`DELETE FROM push_subscriptions WHERE id = ANY($1::int[])`, [stale]);
  }
}

const app = express();
app.set("trust proxy", 1);
const PORT = process.env.PORT || 3001;
const isProduction = process.env.NODE_ENV === "production";

// --- Phone normalization ---
function normalizePhone(phone) {
  if (!phone) return "";
  let digits = phone.replace(/\D/g, "");
  if (digits.length === 10) return `+1${digits}`;
  if (digits.length === 11 && digits.startsWith("1")) return `+${digits}`;
  if (phone.startsWith("+")) return phone.replace(/[^\d+]/g, "");
  return `+${digits}`;
}
function last10(phone) {
  return (phone || "").replace(/\D/g, "").slice(-10);
}

// --- Security / middleware ---
app.use(helmet({ contentSecurityPolicy: false }));

const globalLimiter = rateLimit({
  windowMs: 15 * 60 * 1000,
  max: 500,
  standardHeaders: true,
  legacyHeaders: false,
  message: { error: "Too many requests, please try again later" },
});
app.use(globalLimiter);

const loginLimiter = rateLimit({
  windowMs: 15 * 60 * 1000,
  max: 10,
  standardHeaders: true,
  legacyHeaders: false,
  message: { error: "Too many login attempts, please try again later" },
});

const allowedOrigins = process.env.CORS_ORIGINS
  ? process.env.CORS_ORIGINS.split(",").map((s) => s.trim())
  : [];
app.use(cors({
  origin: allowedOrigins.length > 0
    ? (origin, cb) => (!origin || allowedOrigins.includes(origin)) ? cb(null, true) : cb(new Error("Not allowed by CORS"))
    : false,
  methods: ["GET", "POST", "PUT", "DELETE", "OPTIONS"],
  allowedHeaders: ["Content-Type", "Authorization"],
  credentials: true,
}));

app.use(express.json({ limit: "1mb" }));
app.use(express.urlencoded({ extended: true, limit: "1mb" }));

app.use(session({
  secret: process.env.SESSION_SECRET || crypto.randomBytes(32).toString("hex"),
  resave: false,
  saveUninitialized: false,
  name: "fbc.rsms.sid",
  cookie: {
    httpOnly: true,
    secure: isProduction,
    // 'lax' (not 'strict') so the session cookie survives the top-level
    // redirect from accounts.google.com back to /api/auth/google/callback —
    // 'strict' drops the cookie on any cross-site navigation, breaking OAuth.
    sameSite: "lax",
    maxAge: 8 * 60 * 60 * 1000,
  },
}));

// --- Franchise / user helpers ---
const franchiseCache = new Map(); // id -> franchise row
const twilioClientCache = new Map(); // franchise id -> twilio client

async function loadFranchise(id) {
  if (!id) return null;
  if (franchiseCache.has(id)) return franchiseCache.get(id);
  const { rows } = await db.query(`SELECT * FROM franchises WHERE id = $1`, [id]);
  if (rows.length === 0) return null;
  const franchise = rows[0];
  const { rows: docks } = await db.query(
    `SELECT id, name FROM docks WHERE franchise_id = $1 ORDER BY sort_order`, [id]
  );
  franchise.docks = docks;
  franchiseCache.set(id, franchise);
  return franchise;
}
function invalidateFranchise(id) {
  franchiseCache.delete(id);
  twilioClientCache.delete(id);
}

function getTwilioClient(franchise) {
  if (!franchise || !franchise.twilio_account_sid || !franchise.twilio_auth_token) return null;
  let client = twilioClientCache.get(franchise.id);
  if (!client) {
    client = twilio(franchise.twilio_account_sid, franchise.twilio_auth_token);
    twilioClientCache.set(franchise.id, client);
  }
  return client;
}

async function findFranchiseByInboundTo(toNumber) {
  const normalized = normalizePhone(toNumber);
  const { rows } = await db.query(
    `SELECT * FROM franchises WHERE twilio_phone_number = $1 LIMIT 1`,
    [normalized]
  );
  return rows[0] || null;
}

// --- Auth middleware ---
function requireAuth(req, res, next) {
  if (!req.session || !req.session.userId) {
    return res.status(401).json({ error: "Authentication required" });
  }
  if (req.session.status && req.session.status !== "approved") {
    return res.status(403).json({ error: "Account pending approval", pendingApproval: true, status: req.session.status });
  }
  next();
}

// After auth. Ensures an active franchise is selected. Super-admins must pick
// one before touching tenant-scoped routes (via /api/admin/switch-franchise).
async function requireFranchiseContext(req, res, next) {
  const activeId = req.session.activeFranchiseId;
  if (!activeId) {
    return res.status(409).json({ error: "No active franchise selected", needsFranchiseSelection: true });
  }
  const franchise = await loadFranchise(activeId);
  if (!franchise) return res.status(404).json({ error: "Active franchise no longer exists" });
  req.franchise = franchise;
  req.franchiseId = franchise.id;
  next();
}

function requireSuperAdmin(req, res, next) {
  if (req.session.role !== "super_admin") return res.status(403).json({ error: "Super-admin only" });
  next();
}

// Returns the dock_id the current user is locked to, or null if unrestricted.
// Only franchise_staff with an assigned dock are scoped; admins (super_admin /
// franchise_admin) and legacy staff without a dock see the whole franchise.
function userDockScope(req) {
  if (req.session.role === "franchise_staff" && req.session.dockId) return req.session.dockId;
  return null;
}

// 403s the request if a dock-scoped user is reaching for a dock that isn't
// theirs. Returns true if allowed, false if blocked (and the response is sent).
function denyIfDockOutOfScope(req, res, dockId) {
  const scope = userDockScope(req);
  if (scope && dockId !== scope) {
    res.status(403).json({ error: "Forbidden: this dock is not in your assigned scope" });
    return true;
  }
  return false;
}

// Same idea but for reservation-id endpoints: looks up the reservation and
// 403s/404s if it isn't in the user's dock scope. Returns the reservation row
// when allowed, or null when blocked (response already sent).
async function loadReservationInScope(req, res, reservationId) {
  const { rows } = await db.query(
    `SELECT * FROM reservations WHERE id = $1 AND franchise_id = $2`,
    [reservationId, req.franchiseId]
  );
  if (rows.length === 0) { res.status(404).json({ error: "Reservation not found" }); return null; }
  const scope = userDockScope(req);
  if (scope && rows[0].dock_id !== scope) {
    res.status(403).json({ error: "Forbidden: reservation is at a different dock" });
    return null;
  }
  return rows[0];
}

// --- Hub-trust auth (fbcnefl.com staff hub) ---
// When this instance runs behind the hub's Cloudflare auth-worker, the worker
// authenticates staff against the hub's own session store and forwards their
// identity along with a shared secret. If the secret checks out, establish the
// same session the Google flow would have — hub users never see a second
// login. Requests that reach Railway directly never carry the secret, so they
// fall through to the normal (Google) auth and get nothing.
const hubOriginSecret = process.env.HUB_ORIGIN_SECRET || null;

// Hub "location" strings are free-form ("Jax Beach", "Julington Creek West",
// "Camachee Cove", ...). Map them onto dock ids for Manager dock-scoping.
function hubLocationToDockId(location) {
  const l = (location || "").toLowerCase();
  if (!l) return null;
  if (l.includes("jax") || l.includes("jacksonville")) return "jax-beach";
  if (l.includes("west") || l === "jcw") return "julington-west";
  if (l.includes("julington") || l === "jc") return "julington-east";
  if (l.includes("camachee")) return "camachee-cove";
  if (l.includes("shipyard")) return "shipyard";
  return null;
}

function safeEqual(a, b) {
  const ba = Buffer.from(String(a));
  const bb = Buffer.from(String(b));
  return ba.length === bb.length && crypto.timingSafeEqual(ba, bb);
}

app.use(async (req, res, next) => {
  if (!hubOriginSecret) return next();
  const secret = req.headers["x-origin-auth"];
  const email = String(req.headers["x-hub-email"] || "").toLowerCase().trim();
  if (!secret || !email || !safeEqual(secret, hubOriginSecret)) return next();
  // Already signed in as this person — nothing to do.
  if (req.session && req.session.userId && req.session.email === email) return next();

  const hubRole = String(req.headers["x-hub-role"] || "");
  const name = String(req.headers["x-hub-name"] || "") || null;
  const dockId = (hubRole === "Manager" || hubRole === "Dock Staff")
    ? hubLocationToDockId(req.headers["x-hub-location"])
    : null;

  try {
    const { rows } = await db.query(`SELECT * FROM users WHERE email = $1 LIMIT 1`, [email]);
    let user = rows[0];
    if (!user) {
      // The worker only proxies Admin/Manager/dock-phone hub sessions, but
      // enforce it here too so a worker bug can't mint accounts for other
      // roles. Dock Staff must be dock-scoped — never create an unscoped
      // staff account that would see (and be alerted about) every dock.
      if (hubRole !== "Admin" && hubRole !== "Manager" && hubRole !== "Dock Staff") return next();
      if (hubRole === "Dock Staff" && !dockId) return next();
      const role = hubRole === "Admin" ? "franchise_admin" : "franchise_staff";
      const inserted = await db.query(
        `INSERT INTO users (email, name, role, franchise_id, dock_id, status, approved_at)
         VALUES ($1, $2, $3, 1, $4, 'approved', NOW())
         ON CONFLICT (email) DO UPDATE SET last_login = NOW()
         RETURNING *`,
        [email, name, role, role === "franchise_staff" ? dockId : null]
      );
      user = inserted.rows[0];
    } else {
      // Keep a manager's dock assignment in sync with their hub location on
      // every visit — a staff row with NULL dock_id sees (and is push-notified
      // about) every dock, which is exactly the noise we want to avoid.
      const updated = await db.query(
        `UPDATE users
            SET name = COALESCE(name, $1),
                last_login = NOW(),
                dock_id = CASE
                  WHEN role = 'franchise_staff' AND $2::text IS NOT NULL THEN $2
                  ELSE dock_id
                END
          WHERE id = $3
        RETURNING *`,
        [name, dockId, user.id]
      );
      user = updated.rows[0];
    }
    if (user.status !== "approved") return next();

    req.session.userId = user.id;
    req.session.email = user.email;
    req.session.role = user.role;
    req.session.status = user.status;
    req.session.franchiseId = user.franchise_id;
    req.session.activeFranchiseId = user.franchise_id || 1;
    req.session.dockId = user.dock_id || null;
  } catch (err) {
    console.error("Hub-trust auth failed:", err.message);
  }
  next();
});

// Returns the public origin of this request so OAuth redirects point at the UI the
// user came from. Falls back to host header.
function originFromRequest(req) {
  const proto = (req.headers["x-forwarded-proto"] || req.protocol || "https").split(",")[0].trim();
  const host = req.headers["x-forwarded-host"] || req.get("host");
  return `${proto}://${host}`;
}

// --- Google OAuth ---
const googleClientId = process.env.GOOGLE_CLIENT_ID;
const googleClientSecret = process.env.GOOGLE_CLIENT_SECRET;

function googleRedirectUri(req) {
  if (process.env.GOOGLE_OAUTH_REDIRECT_URL) return process.env.GOOGLE_OAUTH_REDIRECT_URL;
  return `${originFromRequest(req)}/api/auth/google/callback`;
}

function googleOAuthClient(req) {
  if (!googleClientId || !googleClientSecret) return null;
  return new OAuth2Client(googleClientId, googleClientSecret, googleRedirectUri(req));
}

// Kick off the OAuth dance. We sign a CSRF state into the session so the
// callback can prove this exact browser started the flow.
app.get("/api/auth/google", loginLimiter, (req, res) => {
  const client = googleOAuthClient(req);
  if (!client) return res.status(500).json({ error: "Google SSO is not configured" });
  const state = crypto.randomBytes(24).toString("hex");
  req.session.oauthState = state;
  const url = client.generateAuthUrl({
    access_type: "online",
    prompt: "select_account",
    scope: ["openid", "email", "profile"],
    state,
  });
  res.redirect(url);
});

// Callback: verify the ID token, find-or-create the user, set session.
// Brand-new users land in status='pending' with no role/franchise — a
// super_admin must approve them before requireAuth lets them through.
app.get("/api/auth/google/callback", loginLimiter, async (req, res) => {
  const client = googleOAuthClient(req);
  if (!client) return res.status(500).send("Google SSO is not configured");
  const { code, state } = req.query;
  if (!code || !state || state !== req.session.oauthState) {
    return res.redirect("/?sso_error=state");
  }
  delete req.session.oauthState;

  try {
    const { tokens } = await client.getToken(code);
    const ticket = await client.verifyIdToken({ idToken: tokens.id_token, audience: googleClientId });
    const payload = ticket.getPayload();
    if (!payload || !payload.email) return res.redirect("/?sso_error=verify");
    if (!payload.email_verified) return res.redirect("/?sso_error=unverified");

    const email = payload.email.toLowerCase();
    const googleId = payload.sub;
    const fullName = payload.name || null;
    const avatarUrl = payload.picture || null;

    // Match on google_id first, then fall back to email so existing
    // pre-SSO accounts (e.g. the bootstrap super_admin) link cleanly.
    const { rows } = await db.query(
      `SELECT * FROM users WHERE google_id = $1 OR email = $2 ORDER BY (google_id IS NOT NULL) DESC LIMIT 1`,
      [googleId, email]
    );
    let user = rows[0];

    if (!user) {
      const inserted = await db.query(
        `INSERT INTO users (email, google_id, name, avatar_url, status)
         VALUES ($1, $2, $3, $4, 'pending')
         RETURNING *`,
        [email, googleId, fullName, avatarUrl]
      );
      user = inserted.rows[0];
    } else {
      const updated = await db.query(
        `UPDATE users
            SET google_id  = COALESCE(google_id, $1),
                name       = COALESCE($2, name),
                avatar_url = COALESCE($3, avatar_url),
                last_login = NOW()
          WHERE id = $4
        RETURNING *`,
        [googleId, fullName, avatarUrl, user.id]
      );
      user = updated.rows[0];
    }

    req.session.userId = user.id;
    req.session.email = user.email;
    req.session.role = user.role;
    req.session.status = user.status;
    req.session.franchiseId = user.franchise_id;
    req.session.activeFranchiseId = user.franchise_id;
    req.session.dockId = user.dock_id || null;

    res.redirect("/");
  } catch (err) {
    console.error("Google OAuth callback error:", err);
    res.redirect("/?sso_error=exchange");
  }
});

app.post("/api/logout", (req, res) => {
  req.session.destroy((err) => {
    if (err) return res.status(500).json({ error: "Failed to logout" });
    res.clearCookie("fbc.rsms.sid");
    res.json({ success: true });
  });
});

app.get("/api/session", (req, res) => {
  const status = req.session?.status || null;
  const authenticated = !!(req.session && req.session.userId);
  res.json({
    authenticated,
    email: req.session?.email || null,
    role: req.session?.role || null,
    status,
    pendingApproval: authenticated && status && status !== "approved",
    needsFranchiseSelection: authenticated && status === "approved" && !req.session?.activeFranchiseId,
  });
});

// GET /api/me — current user, active franchise, dock list, branding
app.get("/api/me", requireAuth, async (req, res) => {
  try {
    const activeId = req.session.activeFranchiseId;
    let franchise = null;
    let docks = [];
    // Re-read dock_id from the user row in case it was assigned/changed after
    // login; this keeps `req.session.dockId` fresh without forcing a logout.
    const { rows: userRows } = await db.query(
      `SELECT dock_id FROM users WHERE id = $1`, [req.session.userId]
    );
    const userDockId = userRows[0] ? userRows[0].dock_id : null;
    req.session.dockId = userDockId;

    if (activeId) {
      franchise = await loadFranchise(activeId);
      if (franchise) {
        // Dock-scoped users only see their assigned dock in the picker;
        // admins (super_admin / franchise_admin) see all docks.
        const isDockScoped = req.session.role === "franchise_staff" && userDockId;
        const { rows } = isDockScoped
          ? await db.query(
              `SELECT id, name, sort_order FROM docks WHERE franchise_id = $1 AND id = $2`,
              [franchise.id, userDockId]
            )
          : await db.query(
              `SELECT id, name, sort_order FROM docks WHERE franchise_id = $1 ORDER BY sort_order ASC, name ASC`,
              [franchise.id]
            );
        docks = rows;
      }
    }
    res.json({
      user: {
        email: req.session.email,
        role: req.session.role,
        franchiseId: req.session.franchiseId,
        dockId: userDockId,
      },
      franchise: franchise && {
        id: franchise.id, slug: franchise.slug, name: franchise.name,
        timezone: franchise.timezone, logoUrl: franchise.logo_url,
        brandColor: franchise.brand_color,
        twilioConfigured: !!(franchise.twilio_account_sid && franchise.twilio_auth_token),
      },
      docks,
    });
  } catch (err) {
    console.error("/api/me error:", err);
    res.status(500).json({ error: "Failed to load profile" });
  }
});

// --- Super-admin: franchise switcher ---
app.get("/api/admin/franchises", requireAuth, requireSuperAdmin, async (req, res) => {
  const { rows } = await db.query(
    `SELECT id, slug, name, timezone,
            twilio_phone_number,
            (twilio_auth_token IS NOT NULL) AS twilio_configured,
            created_at
     FROM franchises ORDER BY name ASC`
  );
  const { rows: docks } = await db.query(
    `SELECT id, franchise_id, name FROM docks ORDER BY franchise_id, sort_order ASC, name ASC`
  );
  const docksByFranchise = {};
  for (const d of docks) {
    (docksByFranchise[d.franchise_id] = docksByFranchise[d.franchise_id] || []).push({ id: d.id, name: d.name });
  }
  res.json({
    franchises: rows.map((f) => ({ ...f, docks: docksByFranchise[f.id] || [] })),
  });
});

app.post("/api/admin/switch-franchise", requireAuth, requireSuperAdmin, async (req, res) => {
  const { franchiseId } = req.body || {};
  if (!franchiseId) return res.status(400).json({ error: "franchiseId required" });
  const franchise = await loadFranchise(franchiseId);
  if (!franchise) return res.status(404).json({ error: "Franchise not found" });
  req.session.activeFranchiseId = franchise.id;
  res.json({ success: true, franchise: { id: franchise.id, slug: franchise.slug, name: franchise.name } });
});

// --- Super-admin: user approvals ---
const VALID_ROLES = ["super_admin", "franchise_admin", "franchise_staff"];

app.get("/api/admin/users", requireAuth, requireSuperAdmin, async (req, res) => {
  const status = req.query.status || null;
  try {
    const { rows } = await db.query(
      `SELECT u.id, u.email, u.name, u.avatar_url, u.role, u.status,
              u.franchise_id, f.name AS franchise_name,
              u.dock_id, d.name AS dock_name,
              u.created_at, u.last_login, u.approved_at
         FROM users u
         LEFT JOIN franchises f ON f.id = u.franchise_id
         LEFT JOIN docks d ON d.id = u.dock_id
        WHERE ($1::text IS NULL OR u.status = $1)
        ORDER BY
          CASE u.status WHEN 'pending' THEN 0 WHEN 'approved' THEN 1
                       WHEN 'disabled' THEN 2 ELSE 3 END,
          u.created_at DESC`,
      [status]
    );
    res.json({ users: rows });
  } catch (err) {
    console.error("List users error:", err);
    res.status(500).json({ error: "Database error" });
  }
});

// Approve a pending user. super_admin requires franchise_id = NULL;
// franchise_admin/franchise_staff requires a valid franchise_id. A dockId may
// be supplied to scope a franchise_staff user to a single dock; ignored for
// other roles.
app.post("/api/admin/users/:id/approve", requireAuth, requireSuperAdmin, async (req, res) => {
  const targetId = parseInt(req.params.id, 10);
  const { role, franchiseId, dockId } = req.body || {};
  if (!VALID_ROLES.includes(role)) return res.status(400).json({ error: "Invalid role" });
  const wantsFranchise = role !== "super_admin";
  const fid = wantsFranchise ? parseInt(franchiseId, 10) : null;
  if (wantsFranchise && !fid) return res.status(400).json({ error: "franchiseId required for this role" });
  // dockId only meaningful for franchise_staff; silently drop it otherwise.
  const did = role === "franchise_staff" && dockId ? String(dockId) : null;

  try {
    if (fid) {
      const f = await loadFranchise(fid);
      if (!f) return res.status(404).json({ error: "Franchise not found" });
    }
    if (did) {
      const { rows: dockRows } = await db.query(
        `SELECT id FROM docks WHERE id = $1 AND franchise_id = $2`, [did, fid]
      );
      if (dockRows.length === 0) return res.status(400).json({ error: "Dock does not belong to that franchise" });
    }
    const { rows } = await db.query(
      `UPDATE users
          SET role = $1, franchise_id = $2, dock_id = $3, status = 'approved',
              approved_at = NOW(), approved_by = $4
        WHERE id = $5
        RETURNING id, email, role, franchise_id, dock_id, status`,
      [role, fid, did, req.session.userId, targetId]
    );
    if (rows.length === 0) return res.status(404).json({ error: "User not found" });
    res.json({ success: true, user: rows[0] });
  } catch (err) {
    console.error("Approve user error:", err);
    res.status(500).json({ error: err.message || "Failed to approve user" });
  }
});

// Change/clear the dock assignment for an existing user. Only meaningful for
// franchise_staff; passing dockId=null clears the scoping (full franchise access).
app.post("/api/admin/users/:id/dock", requireAuth, requireSuperAdmin, async (req, res) => {
  const targetId = parseInt(req.params.id, 10);
  const { dockId } = req.body || {};
  try {
    const { rows: userRows } = await db.query(
      `SELECT role, franchise_id FROM users WHERE id = $1`, [targetId]
    );
    if (userRows.length === 0) return res.status(404).json({ error: "User not found" });
    const u = userRows[0];
    if (u.role !== "franchise_staff") {
      return res.status(400).json({ error: "Dock scoping only applies to franchise_staff users" });
    }
    const did = dockId ? String(dockId) : null;
    if (did) {
      const { rows: dockRows } = await db.query(
        `SELECT id FROM docks WHERE id = $1 AND franchise_id = $2`, [did, u.franchise_id]
      );
      if (dockRows.length === 0) return res.status(400).json({ error: "Dock does not belong to that user's franchise" });
    }
    const { rows } = await db.query(
      `UPDATE users SET dock_id = $1 WHERE id = $2 RETURNING id, email, role, franchise_id, dock_id`,
      [did, targetId]
    );
    res.json({ success: true, user: rows[0] });
  } catch (err) {
    console.error("Assign dock error:", err);
    res.status(500).json({ error: "Database error" });
  }
});

app.post("/api/admin/users/:id/reject", requireAuth, requireSuperAdmin, async (req, res) => {
  const targetId = parseInt(req.params.id, 10);
  if (targetId === req.session.userId) return res.status(400).json({ error: "Cannot reject yourself" });
  try {
    const { rows } = await db.query(
      `UPDATE users SET status = 'rejected' WHERE id = $1 RETURNING id, email, status`,
      [targetId]
    );
    if (rows.length === 0) return res.status(404).json({ error: "User not found" });
    res.json({ success: true, user: rows[0] });
  } catch (err) {
    console.error("Reject user error:", err);
    res.status(500).json({ error: "Database error" });
  }
});

app.post("/api/admin/users/:id/disable", requireAuth, requireSuperAdmin, async (req, res) => {
  const targetId = parseInt(req.params.id, 10);
  if (targetId === req.session.userId) return res.status(400).json({ error: "Cannot disable yourself" });
  try {
    const { rows } = await db.query(
      `UPDATE users SET status = 'disabled' WHERE id = $1 RETURNING id, email, status`,
      [targetId]
    );
    if (rows.length === 0) return res.status(404).json({ error: "User not found" });
    res.json({ success: true, user: rows[0] });
  } catch (err) {
    console.error("Disable user error:", err);
    res.status(500).json({ error: "Database error" });
  }
});

// --- Feedback (bug / enhancement / general) ---
const FEEDBACK_CATEGORIES = new Set(["bug", "feedback", "enhancement"]);
const FEEDBACK_STATUSES = new Set(["new", "in_progress", "resolved", "wont_fix"]);

const feedbackSubmitLimiter = rateLimit({
  windowMs: 60 * 1000, max: 6,
  standardHeaders: true, legacyHeaders: false,
  message: { error: "Too many feedback submissions, slow down." },
});

const feedbackReadLimiter = rateLimit({
  windowMs: 60 * 1000, max: 60,
  standardHeaders: true, legacyHeaders: false,
});

function feedbackToWire(r, { includeReply = true } = {}) {
  return {
    id: r.id,
    ts: r.created_at,
    category: r.category,
    message: r.message,
    status: r.status,
    page_url: r.page_url,
    ctx_dock: r.ctx_dock,
    ctx_view: r.ctx_view,
    is_known_issue: r.is_known_issue,
    resolved_at: r.resolved_at,
    user_email: r.user_email,
    user_name: r.user_name,
    franchise_id: r.franchise_id,
    ...(includeReply && r.admin_reply
      ? { admin_reply: r.admin_reply, admin_reply_at: r.admin_reply_at }
      : {}),
  };
}

// Submit feedback. Any approved user can post.
app.post("/api/feedback", requireAuth, feedbackSubmitLimiter, async (req, res) => {
  const category = String(req.body?.category || "").toLowerCase();
  const message = String(req.body?.message || "").trim();
  const ctx = req.body?.context || {};
  if (!FEEDBACK_CATEGORIES.has(category)) return res.status(400).json({ error: "Invalid category" });
  if (!message || message.length < 3) return res.status(400).json({ error: "Please include a short description" });
  if (message.length > 4000) return res.status(400).json({ error: "Message too long (max 4000 chars)" });

  try {
    const { rows } = await db.query(
      `INSERT INTO feedback
         (franchise_id, user_id, user_email, user_name, category, message,
          page_url, ctx_dock, ctx_view, user_agent)
       VALUES ($1,$2,$3,$4,$5,$6,$7,$8,$9,$10)
       RETURNING id`,
      [
        req.session.activeFranchiseId || null,
        req.session.userId,
        req.session.email || null,
        req.session.name || null,
        category,
        message,
        ctx.page_url ? String(ctx.page_url).slice(0, 500) : null,
        ctx.dock ? String(ctx.dock).slice(0, 100) : null,
        ctx.view ? String(ctx.view).slice(0, 100) : null,
        (req.get("user-agent") || "").slice(0, 500),
      ]
    );
    res.json({ success: true, id: rows[0].id });
  } catch (err) {
    console.error("Feedback submit error:", err);
    res.status(500).json({ error: "Failed to record feedback" });
  }
});

// The submitter's own feedback, with admin replies attached.
app.get("/api/me/feedback", requireAuth, feedbackReadLimiter, async (req, res) => {
  try {
    const { rows } = await db.query(
      `SELECT * FROM feedback WHERE user_id = $1 ORDER BY id DESC LIMIT 100`,
      [req.session.userId]
    );
    res.json({ success: true, feedback: rows.map((r) => feedbackToWire(r)) });
  } catch (err) {
    console.error("My-feedback error:", err);
    res.status(500).json({ error: "Database error" });
  }
});

// Pinned issues, visible to every approved user. Open issues first, then
// resolved-in-the-last-30-days so techs see what's been fixed recently.
app.get("/api/known-issues", requireAuth, feedbackReadLimiter, async (req, res) => {
  try {
    const { rows } = await db.query(
      `SELECT * FROM feedback
        WHERE is_known_issue = TRUE
          AND (status IN ('new','in_progress')
               OR (status IN ('resolved','wont_fix') AND resolved_at > NOW() - INTERVAL '30 days'))
        ORDER BY
          CASE WHEN status IN ('new','in_progress') THEN 0 ELSE 1 END,
          created_at DESC
        LIMIT 50`
    );
    res.json({ success: true, issues: rows.map((r) => feedbackToWire(r)) });
  } catch (err) {
    console.error("Known-issues error:", err);
    res.status(500).json({ error: "Database error" });
  }
});

// --- Super-admin: feedback triage ---
app.get("/api/admin/feedback", requireAuth, requireSuperAdmin, async (req, res) => {
  const status = req.query.status || null;
  if (status && !FEEDBACK_STATUSES.has(status)) {
    return res.status(400).json({ error: "Invalid status filter" });
  }
  try {
    const { rows } = await db.query(
      `SELECT f.*, fr.name AS franchise_name
         FROM feedback f
         LEFT JOIN franchises fr ON fr.id = f.franchise_id
        WHERE ($1::text IS NULL OR f.status = $1)
        ORDER BY
          CASE f.status WHEN 'new' THEN 0 WHEN 'in_progress' THEN 1 ELSE 2 END,
          f.created_at DESC
        LIMIT 200`,
      [status]
    );
    res.json({ success: true, feedback: rows });
  } catch (err) {
    console.error("Admin feedback list error:", err);
    res.status(500).json({ error: "Database error" });
  }
});

app.post("/api/admin/feedback/:id/status", requireAuth, requireSuperAdmin, async (req, res) => {
  const id = parseInt(req.params.id, 10);
  const status = String(req.body?.status || "");
  if (!id || !FEEDBACK_STATUSES.has(status)) {
    return res.status(400).json({ error: "Invalid id or status" });
  }
  try {
    const isResolution = status === "resolved" || status === "wont_fix";
    const { rows } = await db.query(
      `UPDATE feedback
          SET status = $1,
              resolved_at = CASE
                WHEN $2::boolean THEN COALESCE(resolved_at, NOW())
                ELSE NULL
              END
        WHERE id = $3
        RETURNING *`,
      [status, isResolution, id]
    );
    if (rows.length === 0) return res.status(404).json({ error: "Not found" });
    res.json({ success: true, feedback: rows[0] });
  } catch (err) {
    console.error("Feedback status error:", err);
    res.status(500).json({ error: "Database error" });
  }
});

app.post("/api/admin/feedback/:id/reply", requireAuth, requireSuperAdmin, async (req, res) => {
  const id = parseInt(req.params.id, 10);
  const reply = req.body?.reply == null ? null : String(req.body.reply).trim().slice(0, 4000);
  if (!id) return res.status(400).json({ error: "Invalid id" });
  try {
    const { rows } = await db.query(
      `UPDATE feedback
          SET admin_reply = $1,
              admin_reply_at = CASE WHEN $1 IS NULL THEN NULL ELSE NOW() END
        WHERE id = $2
        RETURNING *`,
      [reply || null, id]
    );
    if (rows.length === 0) return res.status(404).json({ error: "Not found" });
    res.json({ success: true, feedback: rows[0] });
  } catch (err) {
    console.error("Feedback reply error:", err);
    res.status(500).json({ error: "Database error" });
  }
});

app.post("/api/admin/feedback/:id/pin", requireAuth, requireSuperAdmin, async (req, res) => {
  const id = parseInt(req.params.id, 10);
  const pin = !!req.body?.pin;
  if (!id) return res.status(400).json({ error: "Invalid id" });
  try {
    const { rows } = await db.query(
      `UPDATE feedback SET is_known_issue = $1 WHERE id = $2 RETURNING *`,
      [pin, id]
    );
    if (rows.length === 0) return res.status(404).json({ error: "Not found" });
    res.json({ success: true, feedback: rows[0] });
  } catch (err) {
    console.error("Feedback pin error:", err);
    res.status(500).json({ error: "Database error" });
  }
});

app.post("/api/admin/users/:id/reinstate", requireAuth, requireSuperAdmin, async (req, res) => {
  const targetId = parseInt(req.params.id, 10);
  try {
    const { rows } = await db.query(
      `UPDATE users SET status = 'approved' WHERE id = $1 AND status IN ('disabled','rejected')
       RETURNING id, email, status`,
      [targetId]
    );
    if (rows.length === 0) return res.status(404).json({ error: "User not found or already approved" });
    res.json({ success: true, user: rows[0] });
  } catch (err) {
    console.error("Reinstate user error:", err);
    res.status(500).json({ error: "Database error" });
  }
});

// --- Docks (scoped) ---
app.get("/api/docks", requireAuth, requireFranchiseContext, async (req, res) => {
  const { rows } = await db.query(
    `SELECT id, name, sort_order FROM docks WHERE franchise_id = $1 ORDER BY sort_order ASC, name ASC`,
    [req.franchiseId]
  );
  res.json({ docks: rows });
});

// --- Member helpers ---
async function upsertMember(client, franchiseId, phone, name, email) {
  if (!phone) return;
  await client.query(
    `INSERT INTO members (franchise_id, phone, name, email)
     VALUES ($1, $2, $3, $4)
     ON CONFLICT (franchise_id, phone) DO UPDATE
       SET name = COALESCE(EXCLUDED.name, members.name),
           email = COALESCE(NULLIF(EXCLUDED.email, ''), members.email),
           last_seen = NOW()`,
    [franchiseId, phone, name || null, email || null]
  );
}

// Visiting-member lookup: same phone on OTHER franchises. Returns null if
// the phone is only known to the active franchise.
async function findHomeFranchises(activeFranchiseId, phone) {
  if (!phone) return [];
  const { rows } = await db.query(
    `SELECT f.id, f.name, f.slug, m.first_seen
     FROM members m
     JOIN franchises f ON f.id = m.franchise_id
     WHERE m.phone = $1 AND m.franchise_id <> $2
     ORDER BY m.first_seen ASC`,
    [phone, activeFranchiseId]
  );
  return rows;
}

async function findReservationByPhoneInFranchise(franchiseId, phone) {
  const tail = last10(phone);
  if (!tail || !franchiseId) return null;
  // A reply belongs to the member's ACTIVE reservation: today's or the
  // soonest upcoming one (club-local days). Only when nothing is upcoming
  // does it fall back to their most recent past reservation. (Plain
  // "latest date first" routed replies to next week's trip instead of
  // today's when a member had both.)
  const { rows } = await db.query(
    `SELECT * FROM reservations
     WHERE franchise_id = $1
       AND RIGHT(REGEXP_REPLACE(phone, '\\D', '', 'g'), 10) = $2
     ORDER BY
       ((reservation_date AT TIME ZONE '${CLUB_TZ}')::date >= (NOW() AT TIME ZONE '${CLUB_TZ}')::date) DESC NULLS LAST,
       CASE WHEN (reservation_date AT TIME ZONE '${CLUB_TZ}')::date >= (NOW() AT TIME ZONE '${CLUB_TZ}')::date
            THEN reservation_date END ASC,
       reservation_date DESC NULLS LAST, created_at DESC
     LIMIT 1`,
    [franchiseId, tail]
  );
  return rows[0] || null;
}

function rowToReservation(r) {
  return {
    id: r.id,
    name: r.name || "",
    email: r.email || "",
    phone: r.phone || "",
    service: r.service || "Reservation",
    date: r.reservation_date,
    endTime: r.return_time || null,
    memberMobile: r.member_mobile || "",
    contactMobile: r.contact_mobile || "",
    contactHomePhone: r.contact_home_phone || "",
    contactPhone: r.contact_phone || "",
    locationInfo: r.location_info || "",
    guests: r.guests || 1,
    status: r.status || "unconfirmed",
    channel: r.channel || "sms",
    notes: r.notes || "",
    messageSent: !!r.message_sent,
    messageTime: r.message_time,
    timeUpdated: !!r.time_updated,
    originalTime: r.original_time,
    pendingTimeChange: r.pending_time_change || null,
    skipReminder: !!r.skip_reminder,
    dock: r.dock_id,
    sourceId: r.source_id,
    sfStatus: r.sf_status || "",
    sfOutAt: r.sf_out_at || null,
    sfInAt: r.sf_in_at || null,
    cancelledAt: r.cancelled_at || null,
    needsAttention: !!r.needs_attention,
    noReplyShow: !!r.no_reply_show,
    windowStart: r.sf_window_start || null,
    windowEnd: r.sf_window_end || null,
    timeframeName: r.sf_timeframe || "",
    sameDay: !!r.same_day,
    franchiseId: r.franchise_id,
  };
}

// --- Reservations ---

// Reservation dates are stored as timestamptz; "which day" questions are
// always answered in the club's local timezone, not UTC.
const CLUB_TZ = "America/New_York";
function clubDateString(offsetDays = 0) {
  const d = new Date(Date.now() + offsetDays * 86400000);
  return d.toLocaleDateString("en-CA", { timeZone: CLUB_TZ });
}
function resolveDateParam(raw) {
  if (!raw) return null;
  if (raw === "today") return clubDateString(0);
  if (raw === "tomorrow") return clubDateString(1);
  if (/^\d{4}-\d{2}-\d{2}$/.test(raw)) return raw;
  return null;
}

app.get("/api/reservations", requireAuth, requireFranchiseContext, async (req, res) => {
  const dockId = req.query.dock;
  if (!dockId) return res.status(400).json({ error: "Missing dock parameter" });
  if (denyIfDockOutOfScope(req, res, dockId)) return;
  const targetDate = resolveDateParam(req.query.date);
  if (req.query.date && !targetDate) return res.status(400).json({ error: "Invalid date parameter" });

  try {
    // Confirm dock belongs to active franchise
    const { rows: dockRows } = await db.query(
      `SELECT id FROM docks WHERE id = $1 AND franchise_id = $2`,
      [dockId, req.franchiseId]
    );
    if (dockRows.length === 0) return res.status(404).json({ error: "Dock not found for this franchise" });

    // With a date: show that day's reservations from the newest batch that
    // covers the day. Without one: legacy behavior (newest batch, any day).
    const { rows: reservations } = targetDate
      ? await db.query(
          `SELECT * FROM reservations
           WHERE franchise_id = $1 AND dock_id = $2
             AND (reservation_date AT TIME ZONE '${CLUB_TZ}')::date = $3::date
             AND import_batch_id = (
               SELECT MAX(import_batch_id) FROM reservations
               WHERE franchise_id = $1 AND dock_id = $2
                 AND (reservation_date AT TIME ZONE '${CLUB_TZ}')::date = $3::date
             )
           ORDER BY reservation_date ASC NULLS LAST`,
          [req.franchiseId, dockId, targetDate]
        )
      : await db.query(
          `SELECT * FROM reservations
           WHERE franchise_id = $1 AND dock_id = $2
             AND import_batch_id = (
               SELECT MAX(id) FROM import_batches WHERE franchise_id = $1 AND dock_id = $2
             )
           ORDER BY reservation_date ASC NULLS LAST`,
          [req.franchiseId, dockId]
        );

    const phones = [...new Set(reservations.map((r) => r.phone).filter(Boolean))];
    let messagesByPhone = {};
    let visitingByPhone = {};

    if (phones.length > 0) {
      const { rows: messages } = await db.query(
        `SELECT * FROM messages
         WHERE franchise_id = $1 AND phone = ANY($2::text[])
         ORDER BY created_at ASC`,
        [req.franchiseId, phones]
      );
      for (const m of messages) {
        (messagesByPhone[m.phone] = messagesByPhone[m.phone] || []).push({
          from: m.direction === "out" ? "system" : "member",
          text: m.body,
          time: m.created_at,
          twilioSid: m.twilio_sid,
          twilioStatus: m.twilio_status,
          reservationId: m.reservation_id,
        });
      }

      // Visiting-member lookup: same phone registered under other franchises
      const { rows: visits } = await db.query(
        `SELECT m.phone, f.id AS f_id, f.name AS f_name, f.slug AS f_slug
         FROM members m
         JOIN franchises f ON f.id = m.franchise_id
         WHERE m.phone = ANY($1::text[]) AND m.franchise_id <> $2`,
        [phones, req.franchiseId]
      );
      for (const v of visits) {
        (visitingByPhone[v.phone] = visitingByPhone[v.phone] || []).push({
          id: v.f_id, name: v.f_name, slug: v.f_slug,
        });
      }
    }

    const enriched = reservations.map((r) => ({
      ...rowToReservation(r),
      smsLog: messagesByPhone[r.phone] || [],
      homeFranchises: visitingByPhone[r.phone] || [],
    }));

    res.json({ reservations: enriched, dock: dockId, date: targetDate });
  } catch (err) {
    console.error("GET /api/reservations error:", err);
    res.status(500).json({ error: "Database error" });
  }
});

app.post("/api/reservations/import", requireAuth, requireFranchiseContext, async (req, res) => {
  const dockId = req.query.dock || req.body.dock;
  if (!dockId) return res.status(400).json({ error: "Missing dock parameter" });
  if (denyIfDockOutOfScope(req, res, dockId)) return;

  try {
    const { rows: dockRows } = await db.query(
      `SELECT id FROM docks WHERE id = $1 AND franchise_id = $2`,
      [dockId, req.franchiseId]
    );
    if (dockRows.length === 0) return res.status(404).json({ error: "Dock not found for this franchise" });
  } catch (err) {
    console.error("Dock check error:", err);
    return res.status(500).json({ error: "Database error" });
  }

  const { data, merge } = req.body;
  if (!Array.isArray(data) || data.length === 0) {
    return res.status(400).json({ error: "No reservation data provided" });
  }

  try {
    const result = await db.withTx(async (c) => {
      const prefix = dockId.toUpperCase().slice(0, 3);

      // Merge mode: all payload rows are for one club-local day. If a batch
      // already covers that day for this dock, fold the payload into it —
      // update details on matched source_ids, add new ones, and mark rows
      // that vanished from Salesforce as cancelled. Statuses, sent flags and
      // SMS history on existing rows are never reset.
      let batchId = null;
      let targetDate = null;
      if (merge) {
        const firstDated = data.find((r) => r.date);
        if (firstDated) {
          targetDate = new Date(firstDated.date).toLocaleDateString("en-CA", { timeZone: CLUB_TZ });
          const { rows: [existing] } = await c.query(
            `SELECT MAX(import_batch_id) AS id FROM reservations
             WHERE franchise_id = $1 AND dock_id = $2
               AND (reservation_date AT TIME ZONE '${CLUB_TZ}')::date = $3::date`,
            [req.franchiseId, dockId, targetDate]
          );
          batchId = (existing && existing.id) || null;
        }
      }

      const merging = !!batchId;
      let existingBySource = new Map();
      // Next ID suffix comes from the MAX existing suffix, not the row
      // count — fresh imports skip non-Scheduled payload rows, so suffixes
      // can have gaps and the max can exceed the count (count-based seq
      // collided on the primary key).
      let maxExistingSeq = 0;
      if (merging) {
        const { rows: existingRows } = await c.query(
          `SELECT id, source_id, status, time_updated, pending_time_change
           FROM reservations WHERE franchise_id = $1 AND import_batch_id = $2`,
          [req.franchiseId, batchId]
        );
        for (const row of existingRows) {
          if (row.source_id) existingBySource.set(row.source_id, row);
          const n = parseInt(String(row.id).split("-").pop(), 10);
          if (Number.isFinite(n) && n > maxExistingSeq) maxExistingSeq = n;
        }
      } else {
        const { rows: [batch] } = await c.query(
          `INSERT INTO import_batches (franchise_id, dock_id, row_count, uploaded_by_user_id)
           VALUES ($1,$2,$3,$4) RETURNING id`,
          [req.franchiseId, dockId, data.length, req.session.userId]
        );
        batchId = batch.id;
      }

      let added = 0, updated = 0, removed = 0;
      const seenSourceIds = new Set();

      for (let i = 0; i < data.length; i++) {
        const r = data[i];
        const sourceId = r.id || `${prefix}-${String(i + 1).padStart(3, "0")}`;
        seenSourceIds.add(sourceId);
        const normalizedPhone = r.phone ? normalizePhone(r.phone) : "";

        // If this member has been flagged do-not-contact, mark the new
        // reservation skip_reminder=TRUE so it's auto-excluded from bulk send.
        let skipReminder = false;
        if (normalizedPhone) {
          await upsertMember(c, req.franchiseId, normalizedPhone, r.name, r.email);
          const { rows: dncRows } = await c.query(
            `SELECT do_not_contact FROM members WHERE franchise_id = $1 AND phone = $2`,
            [req.franchiseId, normalizedPhone]
          );
          skipReminder = !!(dncRows[0] && dncRows[0].do_not_contact);
        }

        const sfStatus = (r.sfStatus || "").toLowerCase();
        const sfCancelled = sfStatus.startsWith("cancel");
        const match = merging ? existingBySource.get(sourceId) : null;
        if (!match && r.sfStatus && r.sfStatus !== "Scheduled") {
          // Only Scheduled rows become new reservations; Canceled / On The
          // Water / Completed rows ride along purely to update existing ones.
          continue;
        }
        if (match) {
          // A time the member changed by SMS (applied or awaiting approval)
          // beats whatever Salesforce still says — don't stomp it.
          const keepDate = match.time_updated || match.pending_time_change;
          await c.query(
            `UPDATE reservations SET
               phone = $1, name = $2, email = $3, service = $4,
               reservation_date = CASE WHEN $5::boolean THEN reservation_date ELSE $6::timestamptz END,
               return_time = $7, guests = $8, notes = $9,
               member_mobile = $10, contact_mobile = $11, contact_home_phone = $12,
               contact_phone = $13, location_info = $14,
               sf_status = COALESCE($15, sf_status),
               sf_out_at = COALESCE($16::timestamptz, sf_out_at),
               sf_in_at = COALESCE($17::timestamptz, sf_in_at),
               cancelled_at = COALESCE($18::timestamptz, cancelled_at),
               sf_window_start = COALESCE($19::timestamptz, sf_window_start),
               sf_window_end = COALESCE($20::timestamptz, sf_window_end),
               sf_timeframe = COALESCE(NULLIF($21, ''), sf_timeframe)
             WHERE id = $22 AND franchise_id = $23`,
            [
              normalizedPhone, r.name || match.name || "Guest", r.email || "", r.service || "Reservation",
              !!keepDate, r.date || null, r.endTime || null, r.guests || 1, r.notes || "",
              r.memberMobile || "", r.contactMobile || "", r.contactHomePhone || "", r.contactPhone || "", r.locationInfo || "",
              r.sfStatus || null, r.sfOutAt || null, r.sfInAt || null, r.sfCancelledAt || null,
              r.windowStart || null, r.windowEnd || null, r.timeframeName || "",
              match.id, req.franchiseId,
            ]
          );
          updated++;
          // They checked out without ever answering the text — showing up IS
          // the confirmation. Flag it so staff can see who skips replying.
          if ((sfStatus === "on the water" || sfStatus === "completed") &&
              (match.status === "pending" || match.status === "unconfirmed")) {
            await c.query(
              `UPDATE reservations SET status = 'confirmed', no_reply_show = TRUE
               WHERE id = $1 AND franchise_id = $2`,
              [match.id, req.franchiseId]
            );
          }
          if (sfCancelled && match.status !== "cancelled") {
            await c.query(
              `UPDATE reservations SET status = 'cancelled',
                 cancelled_at = COALESCE($3::timestamptz, cancelled_at, NOW())
               WHERE id = $1 AND franchise_id = $2`,
              [match.id, req.franchiseId, r.sfCancelledAt || null]
            );
            removed++;
          }
        } else {
          const seq = merging ? maxExistingSeq + added + 1 : i + 1;
          const reservationId = `F${req.franchiseId}-${prefix}-B${batchId}-${String(seq).padStart(3, "0")}`;
          // A reservation that APPEARS mid-day for today is a same-day
          // call-in — they just booked it, so it's confirmed by definition.
          // (Fresh imports of a whole day keep the normal confirm flow.)
          const sameDayCallIn = merging && targetDate === clubDateString(0);
          await c.query(
            `INSERT INTO reservations
             (id, franchise_id, import_batch_id, source_id, dock_id, phone, name, email, service,
              reservation_date, return_time, guests, status, channel, notes,
              member_mobile, contact_mobile, contact_home_phone, contact_phone, location_info,
              skip_reminder, sf_status, same_day, sf_out_at, sf_in_at, cancelled_at,
              sf_window_start, sf_window_end, sf_timeframe)
             VALUES ($1,$2,$3,$4,$5,$6,$7,$8,$9,$10,$11,$12,$13,$14,$15,$16,$17,$18,$19,$20,$21,$22,$23,$24,$25,$26,$27,$28,$29)`,
            [
              reservationId, req.franchiseId, batchId, sourceId, dockId, normalizedPhone,
              r.name || `Guest ${i + 1}`, r.email || "", r.service || "Reservation",
              r.date || null, r.endTime || null, r.guests || 1,
              sameDayCallIn ? "confirmed" : (r.status || "unconfirmed"), r.channel || "sms", r.notes || "",
              r.memberMobile || "", r.contactMobile || "", r.contactHomePhone || "", r.contactPhone || "", r.locationInfo || "",
              skipReminder, r.sfStatus || null, sameDayCallIn, r.sfOutAt || null, r.sfInAt || null,
              r.sfCancelledAt || null, r.windowStart || null, r.windowEnd || null,
              r.timeframeName || null,
            ]
          );
          added++;
        }
      }

      if (merging) {
        // Rows that came from Salesforce but no longer appear in its feed
        // were cancelled or moved off this day — reflect that.
        for (const [sourceId, row] of existingBySource) {
          if (seenSourceIds.has(sourceId)) continue;
          if (!/^[a-zA-Z0-9]{15,18}$/.test(sourceId)) continue;
          if (row.status === "cancelled") continue;
          await c.query(
            `UPDATE reservations SET status = 'cancelled',
               cancelled_at = COALESCE(cancelled_at, NOW())
             WHERE id = $1 AND franchise_id = $2`,
            [row.id, req.franchiseId]
          );
          removed++;
        }
      }
      // Skipped non-Scheduled rows mean the payload length can overstate
      // what actually landed — recount from the table either way.
      await c.query(
        `UPDATE import_batches SET row_count = (
           SELECT COUNT(*) FROM reservations WHERE import_batch_id = $1
         ) WHERE id = $1 AND franchise_id = $2`,
        [batchId, req.franchiseId]
      );

      return { batchId, count: data.length, merged: merging, added, updated, removed };
    });
    res.json({ success: true, count: result.count, batchId: result.batchId, dock: dockId,
               merged: result.merged, added: result.added, updated: result.updated, removed: result.removed });
  } catch (err) {
    console.error("Import error:", err);
    res.status(500).json({ error: "Import failed", details: err.message });
  }
});

// --- Import history (read-only) ---
// List prior uploads for this franchise, optionally filtered to one dock.
// Each batch shows when it was imported, by whom, the row count, and
// aggregate SMS outcome counts so staff can audit what happened to a batch.
app.get("/api/import-batches", requireAuth, requireFranchiseContext, async (req, res) => {
  // Dock-scoped users see only their own dock's batches, no matter what they
  // ask for. Admins use the optional dock filter as-is.
  const scope = userDockScope(req);
  const dockId = scope || (req.query.dock || null);
  if (req.query.dock && scope && req.query.dock !== scope) {
    return res.status(403).json({ error: "Forbidden: this dock is not in your assigned scope" });
  }
  try {
    const { rows } = await db.query(
      `SELECT
         b.id,
         b.dock_id,
         d.name AS dock_name,
         b.imported_at,
         b.row_count,
         b.uploaded_by_user_id,
         u.email AS uploaded_by_email,
         u.name  AS uploaded_by_name,
         (SELECT COUNT(*)::int FROM reservations r WHERE r.import_batch_id = b.id AND r.status = 'confirmed') AS confirmed_count,
         (SELECT COUNT(*)::int FROM reservations r WHERE r.import_batch_id = b.id AND r.status = 'cancelled') AS cancelled_count,
         (SELECT COUNT(*)::int FROM reservations r WHERE r.import_batch_id = b.id AND r.message_sent)        AS sent_count
       FROM import_batches b
       LEFT JOIN docks d ON d.id = b.dock_id
       LEFT JOIN users u ON u.id = b.uploaded_by_user_id
       WHERE b.franchise_id = $1
         AND ($2::text IS NULL OR b.dock_id = $2)
       ORDER BY b.imported_at DESC
       LIMIT 200`,
      [req.franchiseId, dockId]
    );
    res.json({ batches: rows });
  } catch (err) {
    console.error("List import batches error:", err);
    res.status(500).json({ error: "Database error" });
  }
});

// Read-only snapshot of one batch: the reservations as they were imported,
// plus any SMS exchanged with those phone numbers. Sending/editing is not
// supported here — that's intentional, since acting on a stale batch could
// re-SMS guests whose reservations have since changed.
app.get("/api/import-batches/:id", requireAuth, requireFranchiseContext, async (req, res) => {
  const id = parseInt(req.params.id, 10);
  if (!id) return res.status(400).json({ error: "Invalid batch id" });
  try {
    const { rows: batchRows } = await db.query(
      `SELECT b.*, d.name AS dock_name,
              u.email AS uploaded_by_email,
              u.name  AS uploaded_by_name
         FROM import_batches b
         LEFT JOIN docks d ON d.id = b.dock_id
         LEFT JOIN users u ON u.id = b.uploaded_by_user_id
        WHERE b.id = $1 AND b.franchise_id = $2`,
      [id, req.franchiseId]
    );
    if (batchRows.length === 0) return res.status(404).json({ error: "Batch not found" });
    const batch = batchRows[0];
    if (denyIfDockOutOfScope(req, res, batch.dock_id)) return;

    const { rows: reservations } = await db.query(
      `SELECT * FROM reservations
        WHERE import_batch_id = $1 AND franchise_id = $2
        ORDER BY reservation_date ASC NULLS LAST`,
      [id, req.franchiseId]
    );

    const phones = [...new Set(reservations.map((r) => r.phone).filter(Boolean))];
    const messagesByPhone = {};
    if (phones.length > 0) {
      const { rows: messages } = await db.query(
        `SELECT * FROM messages
         WHERE franchise_id = $1 AND phone = ANY($2::text[])
         ORDER BY created_at ASC`,
        [req.franchiseId, phones]
      );
      for (const m of messages) {
        (messagesByPhone[m.phone] = messagesByPhone[m.phone] || []).push({
          from: m.direction === "out" ? "system" : "member",
          text: m.body,
          time: m.created_at,
          twilioSid: m.twilio_sid,
          twilioStatus: m.twilio_status,
          reservationId: m.reservation_id,
        });
      }
    }

    res.json({
      batch: {
        id: batch.id,
        dockId: batch.dock_id,
        dockName: batch.dock_name,
        importedAt: batch.imported_at,
        rowCount: batch.row_count,
        uploadedBy: batch.uploaded_by_user_id
          ? { id: batch.uploaded_by_user_id, email: batch.uploaded_by_email, name: batch.uploaded_by_name }
          : null,
      },
      reservations: reservations.map((r) => ({
        ...rowToReservation(r),
        smsLog: messagesByPhone[r.phone] || [],
      })),
    });
  } catch (err) {
    console.error("Get import batch error:", err);
    res.status(500).json({ error: "Database error" });
  }
});

app.post("/api/reservations/:id/status", requireAuth, requireFranchiseContext, async (req, res) => {
  const { id } = req.params;
  const { status } = req.body;
  try {
    const inScope = await loadReservationInScope(req, res, id);
    if (!inScope) return;
    const { rows } = await db.query(
      `UPDATE reservations SET status = $1,
         needs_attention = FALSE,
         cancelled_at = CASE WHEN $1 = 'cancelled' THEN COALESCE(cancelled_at, NOW()) ELSE cancelled_at END
       WHERE id = $2 AND franchise_id = $3
       RETURNING *`,
      [status, id, req.franchiseId]
    );
    if (rows.length === 0) return res.status(404).json({ error: "Reservation not found" });
    res.json({ success: true, reservation: rowToReservation(rows[0]) });
  } catch (err) {
    console.error("Status update error:", err);
    res.status(500).json({ error: "Database error" });
  }
});

// Toggle the skip_reminder flag on a single reservation. Bulk send filters out
// reservations where this is TRUE; the individual Send button still works so
// staff can override the skip for one row if they change their mind.
app.post("/api/reservations/:id/skip", requireAuth, requireFranchiseContext, async (req, res) => {
  const { id } = req.params;
  const skip = !!(req.body && req.body.skip);
  try {
    const inScope = await loadReservationInScope(req, res, id);
    if (!inScope) return;
    const { rows } = await db.query(
      `UPDATE reservations SET skip_reminder = $1
       WHERE id = $2 AND franchise_id = $3
       RETURNING *`,
      [skip, id, req.franchiseId]
    );
    if (rows.length === 0) return res.status(404).json({ error: "Reservation not found" });
    res.json({ success: true, reservation: rowToReservation(rows[0]) });
  } catch (err) {
    console.error("Skip toggle error:", err);
    res.status(500).json({ error: "Database error" });
  }
});

// Approve a customer-proposed time change: move pending_time_change into
// reservation_date (backing up the original), clear the pending column, and
// SMS the customer to confirm. Staff invokes this from the dashboard.
app.post("/api/reservations/:id/approve-time-change", requireAuth, requireFranchiseContext, async (req, res) => {
  const { id } = req.params;
  try {
    const { rows } = await db.query(
      `SELECT * FROM reservations WHERE id = $1 AND franchise_id = $2`,
      [id, req.franchiseId]
    );
    if (rows.length === 0) return res.status(404).json({ error: "Reservation not found" });
    const reservation = rows[0];
    if (denyIfDockOutOfScope(req, res, reservation.dock_id)) return;
    if (!reservation.pending_time_change) {
      return res.status(400).json({ error: "No pending time change on this reservation" });
    }
    const originalTime = reservation.original_time || reservation.reservation_date;
    const { rows: updated } = await db.query(
      `UPDATE reservations
       SET reservation_date = $1,
           time_updated = TRUE,
           original_time = COALESCE(original_time, $2),
           pending_time_change = NULL,
           status = 'confirmed',
           needs_sf_push = TRUE
       WHERE id = $3
       RETURNING *`,
      [reservation.pending_time_change, originalTime, id]
    );
    const newTimeStr = new Date(reservation.pending_time_change).toLocaleTimeString("en-US", { hour: "numeric", minute: "2-digit" });
    try {
      await sendAndLogSms(req.franchise, updated[0],
        `Great news! Your new arrival time of ${newTimeStr} is confirmed. See you then!`,
        req.session.userId);
    } catch (err) {
      console.error("Approve time-change SMS error:", err.message);
    }
    res.json({ success: true, reservation: rowToReservation(updated[0]) });
  } catch (err) {
    console.error("Approve time-change error:", err);
    res.status(500).json({ error: "Database error" });
  }
});

app.post("/api/reservations/:id/reject-time-change", requireAuth, requireFranchiseContext, async (req, res) => {
  const { id } = req.params;
  try {
    const { rows } = await db.query(
      `SELECT * FROM reservations WHERE id = $1 AND franchise_id = $2`,
      [id, req.franchiseId]
    );
    if (rows.length === 0) return res.status(404).json({ error: "Reservation not found" });
    const reservation = rows[0];
    if (denyIfDockOutOfScope(req, res, reservation.dock_id)) return;
    if (!reservation.pending_time_change) {
      return res.status(400).json({ error: "No pending time change on this reservation" });
    }
    const requestedTimeStr = new Date(reservation.pending_time_change).toLocaleTimeString("en-US", { hour: "numeric", minute: "2-digit" });
    const originalTimeStr = new Date(reservation.reservation_date).toLocaleTimeString("en-US", { hour: "numeric", minute: "2-digit" });
    const { rows: updated } = await db.query(
      `UPDATE reservations SET pending_time_change = NULL WHERE id = $1 RETURNING *`,
      [id]
    );
    try {
      await sendAndLogSms(req.franchise, updated[0],
        `Sorry — ${requestedTimeStr} isn't available. Your reservation remains at ${originalTimeStr}. Reply YES to confirm or NO if you can't make it.`,
        req.session.userId);
    } catch (err) {
      console.error("Reject time-change SMS error:", err.message);
    }
    res.json({ success: true, reservation: rowToReservation(updated[0]) });
  } catch (err) {
    console.error("Reject time-change error:", err);
    res.status(500).json({ error: "Database error" });
  }
});

// --- SMS building ---
// The default confirmation text, also shown as the starting point in the
// template editor. Keep {placeholders} in sync with TEMPLATE_PLACEHOLDERS.
const DEFAULT_MESSAGE_TEMPLATE =
  "Hi {first_name}! This is a reminder about your upcoming {timeframe} reservation on {date} {time_phrase}.\n\n" +
  "Can you make it? Reply YES to confirm and NO to cancel, or send a new time (e.g. 7:30 AM) if you need to change your arrival.";

const TEMPLATE_PLACEHOLDERS = [
  { token: "{first_name}", label: "Member first name" },
  { token: "{name}", label: "Member full name" },
  { token: "{boat}", label: "Boat / reservation type" },
  { token: "{date}", label: "Reservation date" },
  { token: "{time}", label: "Start time" },
  { token: "{return_time}", label: "Return time" },
  { token: "{time_phrase}", label: "\"at 8:00 AM\" or \"from 8 to 1\"" },
  { token: "{timeframe}", label: "Booked timeframe (Morning / Full Day)" },
  { token: "{dock}", label: "Dock name" },
];

// Mirror of the UI's shortTimeframe(): collapse seasonal names to the class.
function shortTimeframeLabel(name) {
  const n = (name || "").toLowerCase();
  if (!n) return "";
  if (n.includes("full day early return")) return "Full Day (Early Return)";
  if (n.includes("full day")) return "Full Day";
  if (n.includes("morning")) return "Morning";
  if (n.includes("afternoon")) return "Afternoon";
  if (n.includes("evening")) return "Evening";
  if (n.includes("open hours")) return "Open Hours";
  return name;
}

function templateValues(reservation, franchise) {
  // Render in club-local time — the server runs in UTC, so leaving the
  // timezone off would text members times four or five hours ahead.
  const dateObj = new Date(reservation.reservation_date || reservation.date);
  const dateStr = dateObj.toLocaleDateString("en-US", { weekday: "long", month: "long", day: "numeric", timeZone: CLUB_TZ });
  const timeStr = dateObj.toLocaleTimeString("en-US", { hour: "numeric", minute: "2-digit", timeZone: CLUB_TZ });
  const returnRaw = reservation.return_time || reservation.endTime;
  const returnObj = returnRaw ? new Date(returnRaw) : null;
  const returnStr = returnObj && !isNaN(returnObj.getTime())
    ? returnObj.toLocaleTimeString("en-US", { hour: "numeric", minute: "2-digit", timeZone: CLUB_TZ })
    : "";
  const timePhrase = returnStr ? `from ${timeStr} to ${returnStr}` : `at ${timeStr}`;
  // Employee contacts are prefixed "(E) Jane Doe" — texts should say Jane,
  // not "(E)".
  const fullName = (reservation.name || "there").replace(/^\([^)]*\)\s*/, "") || "there";
  const dockName = (franchise && franchise.docks && (franchise.docks.find((d) => d.id === reservation.dock_id) || {}).name)
    || reservation.dock_id || "";
  return {
    "{first_name}": fullName.split(" ")[0],
    "{name}": fullName,
    "{boat}": reservation.service || "reservation",
    "{date}": dateStr,
    "{time}": timeStr,
    "{return_time}": returnStr,
    "{time_phrase}": timePhrase,
    "{timeframe}": shortTimeframeLabel(reservation.sf_timeframe || reservation.timeframeName),
    "{dock}": dockName,
  };
}

function renderTemplate(template, values) {
  return template.replace(/\{[a-z_]+\}/g, (tok) => (tok in values ? values[tok] : tok));
}

function buildSmsBody(reservation, franchise) {
  const template = (franchise && franchise.message_template) || DEFAULT_MESSAGE_TEMPLATE;
  return renderTemplate(template, templateValues(reservation, franchise));
}

async function sendAndLogSms(franchise, reservationRow, customBody, sentByUserId, opts = {}) {
  // markSent: only confirmation-type sends flip message_sent / pending —
  // a weather update or other notice shouldn't make someone look "asked".
  const markSent = opts.markSent !== false;
  const client = getTwilioClient(franchise);
  if (!client) throw new Error(`Twilio is not configured for ${franchise.name}`);
  if (!reservationRow.phone) throw new Error("No phone number on file");
  const toPhone = normalizePhone(reservationRow.phone);
  if (!toPhone || toPhone.length < 10) throw new Error("Invalid phone number format");

  // Custom bodies may still carry {first_name}-style placeholders (e.g. an
  // edited confirmation sent in bulk) — always render per recipient.
  const body = customBody
    ? renderTemplate(customBody, templateValues(reservationRow, franchise))
    : buildSmsBody(reservationRow, franchise);
  const statusCallback = franchise.base_url
    ? `${franchise.base_url.replace(/\/+$/, "")}/api/sms/status`
    : undefined;

  const message = await client.messages.create({
    body,
    ...(franchise.twilio_messaging_service_sid
      ? { messagingServiceSid: franchise.twilio_messaging_service_sid }
      : { from: franchise.twilio_phone_number }),
    to: toPhone,
    statusCallback,
  });

  await db.withTx(async (c) => {
    await c.query(
      `INSERT INTO messages (franchise_id, phone, reservation_id, dock_id, direction, body, twilio_sid, twilio_status, sent_by_user_id)
       VALUES ($1,$2,$3,$4,'out',$5,$6,$7,$8)`,
      [franchise.id, toPhone, reservationRow.id, reservationRow.dock_id, body, message.sid, message.status, sentByUserId || null]
    );
    if (markSent) {
      await c.query(
        `UPDATE reservations
         SET message_sent = TRUE,
             message_time = NOW(),
             status = CASE WHEN status = 'unconfirmed' THEN 'pending' ELSE status END
         WHERE id = $1`,
        [reservationRow.id]
      );
    }
    // Any staff-initiated text counts as the human follow-up.
    await c.query(
      `UPDATE reservations SET needs_attention = FALSE WHERE id = $1 AND needs_attention`,
      [reservationRow.id]
    );
    await upsertMember(c, franchise.id, toPhone, reservationRow.name, reservationRow.email);
  });

  return message;
}

app.post("/api/sms/send/:id", requireAuth, requireFranchiseContext, async (req, res) => {
  const { id } = req.params;
  const { customBody, confirmation } = req.body || {};
  try {
    const reservation = await loadReservationInScope(req, res, id);
    if (!reservation) return;
    const message = await sendAndLogSms(req.franchise, reservation, customBody, req.session.userId,
      { markSent: confirmation !== false });
    const { rows: updated } = await db.query(`SELECT * FROM reservations WHERE id = $1`, [id]);
    res.json({ success: true, messageSid: message.sid, reservation: rowToReservation(updated[0]) });
  } catch (err) {
    console.error("Twilio send error:", err.message);
    res.status(500).json({ error: `Failed to send SMS: ${err.message}`, details: err.message });
  }
});

app.post("/api/sms/send-bulk", requireAuth, requireFranchiseContext, async (req, res) => {
  // body: optional custom message (placeholders render per recipient).
  // confirmation=false (weather update / notice): members who already got
  // their confirmation text are NOT skipped, and the send doesn't mark them
  // as messaged — skip rules below only guard the confirmation flow.
  const { ids, dock: dockId, body: customBody, confirmation } = req.body;
  const isConfirmation = confirmation !== false;
  if (!dockId) return res.status(400).json({ error: "Missing dock parameter" });
  if (denyIfDockOutOfScope(req, res, dockId)) return;

  // Fetch the full candidate set without the eligibility filter so we can
  // report back exactly how many were skipped and why (no phone vs. already
  // sent). The toast in the UI uses these counts to explain a 0-sent result.
  let candidates;
  try {
    if (ids === "all") {
      const { rows } = await db.query(
        `SELECT * FROM reservations
         WHERE franchise_id = $1 AND dock_id = $2
           AND import_batch_id = (SELECT MAX(id) FROM import_batches WHERE franchise_id = $1 AND dock_id = $2)`,
        [req.franchiseId, dockId]
      );
      candidates = rows;
    } else if (Array.isArray(ids)) {
      const { rows } = await db.query(
        `SELECT * FROM reservations
         WHERE id = ANY($1::text[]) AND franchise_id = $2`,
        [ids, req.franchiseId]
      );
      candidates = rows;
    } else {
      return res.status(400).json({ error: "Provide ids array or 'all'" });
    }
  } catch (err) {
    console.error("Bulk target query error:", err);
    return res.status(500).json({ error: "Database error" });
  }

  const requested = candidates.length;
  const skippedNoPhone = candidates.filter((r) => !r.phone).length;
  const skippedAlreadySent = isConfirmation
    ? candidates.filter((r) => r.phone && r.message_sent).length
    : 0;
  const skippedFlagged = candidates.filter((r) => r.phone && (isConfirmation ? !r.message_sent : true) && r.skip_reminder).length;
  const targets = candidates.filter((r) =>
    r.phone && !r.skip_reminder && (isConfirmation ? !r.message_sent : true));

  const results = { sent: 0, failed: 0, errors: [] };
  for (const r of targets) {
    try {
      await sendAndLogSms(req.franchise, r, customBody || undefined, req.session.userId,
        { markSent: isConfirmation });
      results.sent++;
    } catch (err) {
      console.error(`SMS failed for ${r.id}:`, err.message);
      results.failed++;
      results.errors.push({ id: r.id, error: err.message });
    }
  }
  res.json({ success: true, requested, skippedNoPhone, skippedAlreadySent, skippedFlagged, ...results });
});

// --- Admin chat box — send arbitrary SMS to a reservation's phone ---
app.post("/api/sms/simulate", requireAuth, requireFranchiseContext, async (req, res) => {
  const { id, reply } = req.body;
  if (!id || !reply) return res.status(400).json({ error: "Missing id or reply" });

  try {
    const { rows } = await db.query(
      `SELECT * FROM reservations WHERE id = $1 AND franchise_id = $2`,
      [id, req.franchiseId]
    );
    if (rows.length === 0) return res.status(404).json({ error: "Reservation not found" });
    const reservation = rows[0];
    if (denyIfDockOutOfScope(req, res, reservation.dock_id)) return;
    if (!reservation.phone) return res.status(400).json({ error: "No phone number on file for this reservation" });

    const client = getTwilioClient(req.franchise);
    if (!client) return res.status(400).json({ error: `Twilio is not configured for ${req.franchise.name}` });

    const toPhone = normalizePhone(reservation.phone);
    if (!toPhone || toPhone.length < 10) return res.status(400).json({ error: "Invalid phone number format" });

    const message = await client.messages.create({
      body: reply,
      ...(req.franchise.twilio_messaging_service_sid
        ? { messagingServiceSid: req.franchise.twilio_messaging_service_sid }
        : { from: req.franchise.twilio_phone_number }),
      to: toPhone,
      statusCallback: req.franchise.base_url
        ? `${req.franchise.base_url.replace(/\/+$/, "")}/api/sms/status`
        : undefined,
    });

    await db.query(
      `INSERT INTO messages (franchise_id, phone, reservation_id, dock_id, direction, body, twilio_sid, twilio_status, sent_by_user_id)
       VALUES ($1,$2,$3,$4,'out',$5,$6,$7,$8)`,
      [req.franchiseId, toPhone, reservation.id, reservation.dock_id, reply, message.sid, message.status, req.session.userId]
    );
    res.json({ success: true, messageSid: message.sid });
  } catch (err) {
    console.error("Twilio send error (chat):", err.message);
    res.status(500).json({ error: `Failed to send: ${err.message}` });
  }
});

// --- Free-text SMS to a phone in the active franchise ---
// Powers the inline reply box on ConversationDrawer and the "+ New Message"
// composer. Looks up the most recent reservation for that phone (if any)
// to attach a reservation_id / dock_id for context, but works even when
// none exists — i.e., texting a member who has never booked.
app.post("/api/sms/send-to-phone", requireAuth, requireFranchiseContext, async (req, res) => {
  const rawPhone = req.body?.phone;
  const body = String(req.body?.body || "").trim();
  if (!rawPhone) return res.status(400).json({ error: "Missing phone" });
  if (!body) return res.status(400).json({ error: "Message body is empty" });
  if (body.length > 1600) return res.status(400).json({ error: "Message too long (max 1600 chars)" });

  const toPhone = normalizePhone(rawPhone);
  if (!toPhone || toPhone.replace(/\D/g, "").length < 10) {
    return res.status(400).json({ error: "Invalid phone number" });
  }

  const client = getTwilioClient(req.franchise);
  if (!client) return res.status(400).json({ error: `Twilio is not configured for ${req.franchise.name}` });

  try {
    const { rows: resvRows } = await db.query(
      `SELECT id, dock_id, name, email FROM reservations
        WHERE franchise_id = $1 AND phone = $2
        ORDER BY reservation_date DESC NULLS LAST, created_at DESC
        LIMIT 1`,
      [req.franchiseId, toPhone]
    );
    const ctx = resvRows[0] || null;

    // Dock-scoped users may only message phones tied to a reservation at their
    // dock. No matching reservation (or wrong dock) is a 403.
    const scope = userDockScope(req);
    if (scope && (!ctx || ctx.dock_id !== scope)) {
      return res.status(403).json({ error: "Forbidden: recipient is not at your dock" });
    }

    const message = await client.messages.create({
      body,
      ...(req.franchise.twilio_messaging_service_sid
        ? { messagingServiceSid: req.franchise.twilio_messaging_service_sid }
        : { from: req.franchise.twilio_phone_number }),
      to: toPhone,
      statusCallback: req.franchise.base_url
        ? `${req.franchise.base_url.replace(/\/+$/, "")}/api/sms/status`
        : undefined,
    });

    await db.withTx(async (c) => {
      await c.query(
        `INSERT INTO messages (franchise_id, phone, reservation_id, dock_id, direction, body, twilio_sid, twilio_status, sent_by_user_id)
         VALUES ($1,$2,$3,$4,'out',$5,$6,$7,$8)`,
        [
          req.franchiseId, toPhone,
          ctx ? ctx.id : null, ctx ? ctx.dock_id : null,
          body, message.sid, message.status, req.session.userId,
        ]
      );
      await upsertMember(c, req.franchiseId, toPhone, ctx ? ctx.name : null, ctx ? ctx.email : null);
    });

    res.json({ success: true, messageSid: message.sid, phone: toPhone });
  } catch (err) {
    console.error("send-to-phone error:", err.message);
    res.status(500).json({ error: `Failed to send: ${err.message}` });
  }
});

// --- Bulk free-text SMS to multiple phones in the active franchise ---
// Same body for everyone. Dedupes normalized phones, validates each, then
// sends sequentially so a single Twilio error doesn't abort the run. Returns
// per-recipient outcomes so the UI can surface partial failures.
app.post("/api/sms/send-to-phones", requireAuth, requireFranchiseContext, async (req, res) => {
  const rawPhones = Array.isArray(req.body?.phones) ? req.body.phones : [];
  const body = String(req.body?.body || "").trim();
  if (rawPhones.length === 0) return res.status(400).json({ error: "Missing phones" });
  if (!body) return res.status(400).json({ error: "Message body is empty" });
  if (body.length > 1600) return res.status(400).json({ error: "Message too long (max 1600 chars)" });
  if (rawPhones.length > 200) return res.status(400).json({ error: "Too many recipients (max 200 per send)" });

  const client = getTwilioClient(req.franchise);
  if (!client) return res.status(400).json({ error: `Twilio is not configured for ${req.franchise.name}` });

  // Normalize + dedupe before sending so we don't double-text someone whose
  // phone appeared twice in the recipient list (autocomplete + raw entry).
  const normalized = [];
  const seen = new Set();
  const invalid = [];
  for (const raw of rawPhones) {
    const p = normalizePhone(raw);
    if (!p || p.replace(/\D/g, "").length < 10) {
      invalid.push(raw);
      continue;
    }
    if (seen.has(p)) continue;
    seen.add(p);
    normalized.push(p);
  }

  const statusCallback = req.franchise.base_url
    ? `${req.franchise.base_url.replace(/\/+$/, "")}/api/sms/status`
    : undefined;
  const fromArgs = req.franchise.twilio_messaging_service_sid
    ? { messagingServiceSid: req.franchise.twilio_messaging_service_sid }
    : { from: req.franchise.twilio_phone_number };

  const scope = userDockScope(req);
  const results = { sent: 0, failed: 0, errors: [] };
  for (const toPhone of normalized) {
    try {
      const { rows: resvRows } = await db.query(
        `SELECT id, dock_id, name, email FROM reservations
          WHERE franchise_id = $1 AND phone = $2
          ORDER BY reservation_date DESC NULLS LAST, created_at DESC
          LIMIT 1`,
        [req.franchiseId, toPhone]
      );
      const ctx = resvRows[0] || null;

      if (scope && (!ctx || ctx.dock_id !== scope)) {
        results.failed++;
        results.errors.push({ phone: toPhone, error: "Recipient not at your dock" });
        continue;
      }

      const message = await client.messages.create({
        body, to: toPhone, statusCallback, ...fromArgs,
      });

      await db.withTx(async (c) => {
        await c.query(
          `INSERT INTO messages (franchise_id, phone, reservation_id, dock_id, direction, body, twilio_sid, twilio_status, sent_by_user_id)
           VALUES ($1,$2,$3,$4,'out',$5,$6,$7,$8)`,
          [
            req.franchiseId, toPhone,
            ctx ? ctx.id : null, ctx ? ctx.dock_id : null,
            body, message.sid, message.status, req.session.userId,
          ]
        );
        await upsertMember(c, req.franchiseId, toPhone, ctx ? ctx.name : null, ctx ? ctx.email : null);
      });

      results.sent++;
    } catch (err) {
      console.error(`send-to-phones failed for ${toPhone}:`, err.message);
      results.failed++;
      results.errors.push({ phone: toPhone, error: err.message });
    }
  }

  res.json({
    success: true,
    requested: rawPhones.length,
    deduped: normalized.length,
    invalid: invalid.length,
    ...results,
  });
});

// --- Members directory (for the new-message composer's autocomplete) ---
// Returns members of the active franchise, name+phone+email only. Search
// is a case-insensitive substring match on name or phone digits.
app.get("/api/members", requireAuth, requireFranchiseContext, async (req, res) => {
  const q = String(req.query.q || "").trim().toLowerCase();
  const qDigits = q.replace(/\D/g, "");
  const limit = Math.min(parseInt(req.query.limit, 10) || 50, 200);
  const scope = userDockScope(req);
  try {
    // Dock-scoped users only see members who have at least one reservation at
    // their dock (in this franchise). Admins see all members in the franchise.
    const { rows } = await db.query(
      `SELECT m.phone, m.name, m.email, m.first_seen, m.last_seen, m.do_not_contact
         FROM members m
        WHERE m.franchise_id = $1
          AND ($2 = ''
               OR LOWER(COALESCE(m.name, '')) LIKE '%' || $2 || '%'
               OR ($3 <> '' AND REGEXP_REPLACE(m.phone, '\\D', '', 'g') LIKE '%' || $3 || '%'))
          AND ($5::text IS NULL OR EXISTS (
            SELECT 1 FROM reservations r
             WHERE r.phone = m.phone AND r.franchise_id = m.franchise_id AND r.dock_id = $5
          ))
        ORDER BY m.last_seen DESC NULLS LAST, m.name ASC
        LIMIT $4`,
      [req.franchiseId, q, qDigits, limit, scope]
    );
    res.json({ members: rows });
  } catch (err) {
    console.error("List members error:", err);
    res.status(500).json({ error: "Database error" });
  }
});

// Toggle the member-level do-not-contact flag. Dock-scoped staff may only flip
// it on members who have a reservation at their dock — otherwise it's a
// franchise-wide flag and admins maintain it.
app.post("/api/members/:phone/dnc", requireAuth, requireFranchiseContext, async (req, res) => {
  const phone = normalizePhone(req.params.phone);
  const dnc = !!(req.body && req.body.dnc);
  if (!phone) return res.status(400).json({ error: "Invalid phone" });
  const scope = userDockScope(req);
  try {
    if (scope) {
      const { rows: check } = await db.query(
        `SELECT 1 FROM reservations
          WHERE franchise_id = $1 AND phone = $2 AND dock_id = $3 LIMIT 1`,
        [req.franchiseId, phone, scope]
      );
      if (check.length === 0) {
        return res.status(403).json({ error: "Forbidden: member is not in your dock's scope" });
      }
    }
    const { rows } = await db.query(
      `UPDATE members SET do_not_contact = $1
        WHERE franchise_id = $2 AND phone = $3
        RETURNING phone, name, email, do_not_contact`,
      [dnc, req.franchiseId, phone]
    );
    if (rows.length === 0) return res.status(404).json({ error: "Member not found" });
    res.json({ success: true, member: rows[0] });
  } catch (err) {
    console.error("DNC toggle error:", err);
    res.status(500).json({ error: "Database error" });
  }
});

// --- Inbound reply parsing (Postgres-native) ---
//
// Resolution order:
//   1. Strict patterns (exact one-word replies like YES / NO / CANCEL).
//      Free, deterministic, and instant — no API call.
//   2. Claude (Haiku 4.5) intent classification — handles paraphrasing,
//      mixed signals, and natural language the regex can't reason about.
//   3. Loose regex fallback tiers — only reached if Claude is unavailable
//      (no API key, network error, timeout) or returned "unknown".
//
// Cancel is checked before confirm at every tier — mis-confirming a cancel is
// the costlier failure mode of the two.
const CONFIRM_RESPONSE = "Thank you! Your reservation is confirmed. We look forward to seeing you!";
const CANCEL_RESPONSE = "Your reservation has been cancelled. If you change your mind, please call us to rebook.";
const DOCK_PHONES = {
  "jax-beach": "904-562-8676",
  "julington-east": "904-625-1847",
  "julington-west": "904-874-6314",
  "camachee-cove": "904-562-8842",
  "shipyard": "904-710-1358",
};
// This line does exactly three things: confirm, cancel, change arrival
// time. Everything else gets redirected to a phone call — no "someone will
// follow up" promises (though staff still see the thread and the row flag).
const DOCK_PHONE_LIST =
  `• Jacksonville Beach: 904-562-8676\n` +
  `• Julington Creek East: 904-625-1847\n` +
  `• Julington Creek West (Pontoons Only): 904-874-6314\n` +
  `• Camachee Cove: 904-562-8842\n` +
  `• St. Augustine Shipyard: 904-710-1358`;
const HANDOFF_PREFIX = "This line is just for confirming, canceling, or changing arrival times";
function handoffResponse() {
  return (
    `${HANDOFF_PREFIX} on existing reservations. For anything else — same-day bookings, ` +
    `boat type changes, new reservations, or questions — please give the dock a call:\n` +
    DOCK_PHONE_LIST
  );
}
// Member says they're late but gave no time — the one thing the bot can fix
// on its own is the arrival time, so ask for it instead of handing off.
const RUNNING_LATE_RESPONSE =
  "No problem — thanks for the heads up! What time should we expect you? " +
  "Reply with a new arrival time (like \"10:30 AM\") and we'll update your reservation.";
const ROBOTIC_FALLBACK =
  "Sorry, I didn't catch that! Reply YES to confirm your reservation, NO to cancel, " +
  "or a new arrival time like \"9:30\".\n\nFor anything else, please call the dock:\n" +
  DOCK_PHONE_LIST;

async function applyCancel(reservation) {
  await db.query(
    `UPDATE reservations SET status = 'cancelled', cancelled_at = NOW() WHERE id = $1`,
    [reservation.id]
  );
  return CANCEL_RESPONSE;
}

async function applyConfirm(reservation) {
  await db.query(`UPDATE reservations SET status = 'confirmed' WHERE id = $1`, [reservation.id]);
  return CONFIRM_RESPONSE;
}

// We don't have an availability source of truth — the FBC booking system
// is external — so we never auto-apply a time change. Instead we record the
// proposed time on the reservation row and surface it in the dashboard for
// staff to approve or reject. The customer gets a "we'll check" reply.
async function flagTimeChangeRequest(reservation, hour, minute) {
  const start = new Date(reservation.reservation_date);
  // Build the requested time as CLUB-LOCAL wall time on the reservation's
  // day (setHours would use the server's clock, which runs UTC).
  const etDate = start.toLocaleDateString("en-CA", { timeZone: CLUB_TZ });
  const tzPart = new Intl.DateTimeFormat("en-US", { timeZone: CLUB_TZ, timeZoneName: "longOffset" })
    .formatToParts(start).find((p) => p.type === "timeZoneName");
  const offset = (tzPart && tzPart.value.replace("GMT", "")) || "-05:00";
  const requested = new Date(`${etDate}T${String(hour).padStart(2, "0")}:${String(minute).padStart(2, "0")}:00${offset}`);
  const newTimeStr = requested.toLocaleTimeString("en-US", { hour: "numeric", minute: "2-digit", timeZone: CLUB_TZ });

  // Auto-apply bounds: the BOOKED TIMEFRAME when we have it — that's what
  // the member is entitled to (often a whole-day block), even if their
  // planned arrival was later. Fall back to planned arrival→return. We move
  // ONLY the arrival; anything outside the window needs staff approval.
  const winStart = reservation.sf_window_start ? new Date(reservation.sf_window_start) : start;
  const winEnd = reservation.sf_window_end ? new Date(reservation.sf_window_end)
    : (reservation.return_time ? new Date(reservation.return_time) : null);
  const withinWindow = winEnd && !isNaN(winEnd.getTime()) &&
    requested.getTime() >= winStart.getTime() && requested.getTime() <= winEnd.getTime();

  if (withinWindow) {
    await db.query(
      `UPDATE reservations
         SET reservation_date = $1,
             time_updated = TRUE,
             original_time = COALESCE(original_time, $2),
             pending_time_change = NULL,
             status = 'confirmed',
             needs_sf_push = TRUE
       WHERE id = $3`,
      [requested.toISOString(), reservation.reservation_date, reservation.id]
    );
    return `You're all set — we've updated your arrival to ${newTimeStr}. See you then!`;
  }

  await db.query(
    `UPDATE reservations SET pending_time_change = $1 WHERE id = $2`,
    [requested.toISOString(), reservation.id]
  );
  return `Thanks! ${newTimeStr} is outside your booked window, so we'll check with the dock and confirm shortly.`;
}

async function parseAndApplyReply(inboundText, reservation) {
  // Apostrophes vanish ("I'm"→"im", "won't"→"wont"); other punctuation
  // becomes a SPACE so "9-10am" reads "9 10am", not "910am" — members text
  // contractions and dash ranges constantly.
  const replyLower = inboundText.toLowerCase()
    .replace(/['’]/g, "")
    .replace(/[^a-z0-9\s:]/g, " ")
    .replace(/\s+/g, " ")
    .trim();

  const confirmPatterns = /^(confirm|confirmed|yes|yep|yeah|yea|yup|y|c|ok|okay|sure|sounds good|good|great|absolutely|perfect|see you there|will be there|we will be there|ill be there|looking forward|affirmative)$/;
  const confirmLoose = /(confirm|yes|yep|yeah|yup|sounds good|okay|ok sure|absolutely|perfect|see you (there|soon|then|at)|will be there|looking forward|count me in|im in|we're in|all good|good to go)/;
  const cancelPatterns = /^(cancel|cancelled|no|nope|nah|n|cant make it|can not make it|cannot make it|wont be there|not coming|count me out|remove|pass)$/;
  const cancelLoose = /(cancel|cant make it|can not make it|cannot make it|wont be there|not coming|count me out|wont( be able to)? make it|will not( be able to)? make it|unable to make it|not( be)? able to make it)/;
  const timeMatch = replyLower.match(
    /(?:time|change.*time|move.*to|reschedule.*to|change.*to|switch.*to|make it|new time)?\s*(\d{1,2}):?(\d{2})?\s*(am|pm)/i
  );
  // Times WITHOUT am/pm only count with a colon ("5:00") or arrival context
  // ("coming at 5", "eta 5") — so "2 guests" never parses as 2 o'clock.
  // Meridiem inference: 1–6 reads as afternoon, 7–12 as morning/noon.
  const bareTime = !timeMatch && (
    replyLower.match(/(\d{1,2}):(\d{2})(?!\s*(?:am|pm))/) ||
    // The whole message is just a number — "11", "930", "9 30": on this
    // line, a bare number means an arrival time.
    replyLower.match(/^\s*(\d{1,2})\s?(\d{2})?\s*$/) ||
    // With arrival/correction context: "coming at 930", "eta 10",
    // "actually 1045", "make that 11"
    replyLower.match(/(?:arriv\w+|coming|be there|eta|around|actually|instead|make (?:it|that)|move to|updat\w+(?: to)?|\bat)\s+(\d{1,2}):?(\d{2})?\b/)
  );
  const namedTime = /\bnoon\b/.test(replyLower) ? { h: 12, m: 0 }
    : /\bmidnight\b/.test(replyLower) ? { h: 0, m: 0 } : null;
  const handoffOrInquiry = /(human|real person|talk to|speak to|chat with|customer service|live person|representative|\bagent\b|\bmanager\b|do you have|any boats|boats? avail|any avail|any open|any slot|any free|reservation for|reserve a|book (a|another)|want to book|new booking)/;

  if (!reservation) {
    return "Hi there! This line is just for confirming, canceling, or changing times on existing reservations.\n\n" +
      "For anything else, call Member Service at 904-544-4204 or your dock directly:\n" +
      "• Jacksonville Beach: 904-562-8676\n" +
      "• Julington Creek East: 904-625-1847\n" +
      "• Julington Creek West (Pontoons Only): 904-874-6314\n" +
      "• Camachee Cove: 904-562-8842\n" +
      "• St. Augustine Shipyard: 904-710-1358";
  }

  // Pleasantries and bare emoji end the thread gracefully — no auto-reply
  // at all (returning null sends nothing), never "sorry I didn't catch that".
  if (replyLower === "" ||
      /^(ok |okay |great |perfect |awesome )?(thanks|thank you|thank u|thanks so much|thank you so much|thanks a lot|thx|ty|tysm|got it|gotcha|appreciate it|much appreciated|no problem|np|will do|you too|have a good (day|one|weekend))[!. ]*$/.test(replyLower) ||
      // Apology follow-ups after a cancel ("I am sorry for the short notice")
      /^(i am |im |we are |were )?(so |really |very )?sorry( for| about)?( the| that| this)?( short)?( notice)?[!. ]*$/.test(replyLower)) {
    return null;
  }

  // Tier 1 — strict patterns. Catches the common short replies instantly.
  if (cancelPatterns.test(replyLower)) return applyCancel(reservation);
  if (confirmPatterns.test(replyLower)) return applyConfirm(reservation);

  // LLM tier deliberately OFF (10/4, Mackenzie): the line runs like a
  // doctor's office — strict menu, predictable replies, zero API cost.
  // lib/intent.js is dormant; re-wire classifyIntent() here to re-enable.

  // Tier 2 — loose regex.
  // Negated cancel ("I don't want to cancel") means KEEP the reservation —
  // without this guard the loose cancel pattern below would cancel them.
  if (/(don'?t|do not|dont|no need to|not going to|won'?t)\s+(want to\s+|wanna\s+|need to\s+)?cancel/.test(replyLower)) {
    return applyConfirm(reservation);
  }
  if (cancelLoose.test(replyLower)) return applyCancel(reservation);
  // A time beats a loose confirm: "Yes. 11am pick up" should RECORD 11am —
  // applying the time also confirms them, so nothing is lost.
  if (timeMatch) {
    let h = parseInt(timeMatch[1]);
    const m = parseInt(timeMatch[2] || "0");
    const ampm = timeMatch[3];
    if (ampm && ampm.toLowerCase() === "pm" && h < 12) h += 12;
    if (ampm && ampm.toLowerCase() === "am" && h === 12) h = 0;
    if (h >= 0 && h <= 23 && m >= 0 && m <= 59) return flagTimeChangeRequest(reservation, h, m);
  }
  if (namedTime) return flagTimeChangeRequest(reservation, namedTime.h, namedTime.m);
  if (bareTime) {
    let h = parseInt(bareTime[1]);
    const m = parseInt(bareTime[2] || "0");
    if (h >= 1 && h <= 6) h += 12; // "5" on a boat dock means 5 PM
    if (h >= 0 && h <= 23 && m >= 0 && m <= 59) return flagTimeChangeRequest(reservation, h, m);
  }
  if (confirmLoose.test(replyLower)) return applyConfirm(reservation);
  if (/(running late|gonna be late|going to be late|be a (little|bit) late|bit behind|behind schedule|stuck in traffic|push (it )?back|be there later|come later|little later)/.test(replyLower)) {
    return RUNNING_LATE_RESPONSE;
  }
  if (handoffOrInquiry.test(replyLower) || inboundText.includes("?")) {
    return handoffResponse();
  }

  return ROBOTIC_FALLBACK;
}

// --- Twilio inbound webhook ---
// Routes by the `To` number to the franchise, then validates the signature
// with THAT franchise's auth token before trusting the request.
app.post("/api/sms/incoming", express.urlencoded({ extended: false }), async (req, res) => {
  const { From, To, Body } = req.body;
  const franchise = await findFranchiseByInboundTo(To);

  if (!franchise) {
    console.warn(`Inbound SMS to unknown number: ${To}`);
    return res.status(404).send("Unknown recipient");
  }

  // Validate Twilio signature with this franchise's auth token, in prod only.
  if (isProduction && franchise.twilio_auth_token) {
    const signature = req.headers["x-twilio-signature"];
    const url = (franchise.base_url ? franchise.base_url.replace(/\/+$/, "") : "") + "/api/sms/incoming";
    const valid = twilio.validateRequest(franchise.twilio_auth_token, signature, url, req.body);
    if (!valid) {
      console.warn(`Invalid Twilio signature for franchise ${franchise.id}`);
      return res.status(403).send("Invalid signature");
    }
  }

  const inboundText = (Body || "").trim();
  const normalizedFrom = normalizePhone(From);

  let responseText;
  try {
    const reservation = await findReservationByPhoneInFranchise(franchise.id, From);

    await db.query(
      `INSERT INTO messages (franchise_id, phone, reservation_id, dock_id, direction, body)
       VALUES ($1,$2,$3,$4,'in',$5)`,
      [franchise.id, normalizedFrom, reservation ? reservation.id : null,
       reservation ? reservation.dock_id : null, inboundText]
    );
    await db.withTx(async (c) => {
      await upsertMember(c, franchise.id, normalizedFrom, reservation ? reservation.name : null, null);
    });

    // Only treat the text as being ABOUT a reservation when that reservation
    // is live (today or upcoming, club-local). Someone whose last trip was
    // last month texting "any boats tomorrow?" gets the general greeting —
    // the bot shouldn't assume they mean a long-finished booking. The thread
    // still logs under their old dock so staff can see and reply.
    const resDay = reservation && reservation.reservation_date
      ? new Date(reservation.reservation_date).toLocaleDateString("en-CA", { timeZone: CLUB_TZ })
      : null;
    const activeReservation = reservation && resDay && resDay >= clubDateString(0) ? reservation : null;

    responseText = await parseAndApplyReply(inboundText, activeReservation);

    // Bot punted to a human — flag the row so dock staff see it needs them.
    if (activeReservation && responseText && (responseText.startsWith(HANDOFF_PREFIX) || responseText === ROBOTIC_FALLBACK)) {
      await db.query(
        `UPDATE reservations SET needs_attention = TRUE WHERE id = $1`,
        [activeReservation.id]
      );
    }

    if (responseText) {
      await db.query(
        `INSERT INTO messages (franchise_id, phone, reservation_id, dock_id, direction, body)
         VALUES ($1,$2,$3,$4,'out',$5)`,
        [franchise.id, normalizedFrom, reservation ? reservation.id : null,
         reservation ? reservation.dock_id : null, responseText]
      );
    }

    // Fire-and-forget push to relevant staff devices. Admins always get it;
    // franchise_staff only get it if the reservation's dock matches theirs.
    // No reservation = orphan inbound = admins only. Don't await — Twilio
    // needs a prompt response.
    const senderName = reservation && reservation.name ? reservation.name : normalizedFrom;
    const dockForPush = reservation ? reservation.dock_id : null;
    pushForInbound(franchise.id, dockForPush, {
      title: `New SMS from ${senderName}`,
      body: inboundText.slice(0, 160),
      phone: normalizedFrom,
      dockId: dockForPush,
      url: `/dashboard?phone=${encodeURIComponent(normalizedFrom)}`,
    }).catch((e) => console.error("Push fan-out error:", e && e.message));
  } catch (err) {
    console.error("Inbound webhook error:", err);
    responseText = "We received your message but something went wrong on our end. Please try again shortly.";
  }

  const twiml = new twilio.twiml.MessagingResponse();
  if (responseText) twiml.message(responseText);
  res.type("text/xml").send(twiml.toString());
});

// Delivery-status callback. We don't bother validating signature here — the
// worst case is a bogus status flag, and the SID is the join key anyway.
app.post("/api/sms/status", express.urlencoded({ extended: false }), async (req, res) => {
  const { MessageSid, MessageStatus } = req.body;
  try {
    await db.query(
      `UPDATE messages SET twilio_status = $1 WHERE twilio_sid = $2`,
      [MessageStatus, MessageSid]
    );
  } catch (err) {
    console.error("Status callback error:", err);
  }
  res.sendStatus(200);
});

// --- Conversations (scoped) ---
app.get("/api/sms/log/:id", requireAuth, requireFranchiseContext, async (req, res) => {
  const { id } = req.params;
  try {
    const reservation = await loadReservationInScope(req, res, id);
    if (!reservation) return;

    const { rows: messages } = await db.query(
      `SELECT * FROM messages WHERE franchise_id = $1 AND phone = $2 ORDER BY created_at ASC`,
      [req.franchiseId, reservation.phone]
    );
    const homeFranchises = await findHomeFranchises(req.franchiseId, reservation.phone);
    res.json({
      reservation: rowToReservation(reservation),
      homeFranchises,
      smsLog: messages.map((m) => ({
        from: m.direction === "out" ? "system" : "member",
        text: m.body,
        time: m.created_at,
        twilioSid: m.twilio_sid,
        twilioStatus: m.twilio_status,
        reservationId: m.reservation_id,
      })),
    });
  } catch (err) {
    console.error("SMS log fetch error:", err);
    res.status(500).json({ error: "Database error" });
  }
});

app.get("/api/conversations", requireAuth, requireFranchiseContext, async (req, res) => {
  const scope = userDockScope(req);
  try {
    // For dock-scoped users, only surface conversations whose most-recent
    // reservation in this franchise sits at their dock. Phones with no
    // reservation at all are hidden (admins still see them).
    const { rows } = await db.query(
      `SELECT
         m.phone,
         COALESCE(mem.name, r_last.name) AS name,
         mem.email,
         COUNT(*)::int AS message_count,
         MAX(m.created_at) AS last_message_at,
         MAX(m.created_at) FILTER (WHERE m.direction = 'in') AS last_inbound_at,
         (ARRAY_AGG(m.body ORDER BY m.created_at DESC))[1] AS last_message_body,
         (ARRAY_AGG(m.direction ORDER BY m.created_at DESC))[1] AS last_direction,
         (ARRAY_AGG(m.dock_id ORDER BY m.created_at DESC))[1] AS last_dock_id,
         r_last.status AS res_status
       FROM messages m
       LEFT JOIN members mem ON mem.phone = m.phone AND mem.franchise_id = m.franchise_id
       LEFT JOIN LATERAL (
         SELECT name, dock_id, status FROM reservations r
         WHERE r.phone = m.phone AND r.franchise_id = m.franchise_id
         ORDER BY r.created_at DESC LIMIT 1
       ) r_last ON TRUE
       WHERE m.franchise_id = $1
         AND ($2::text IS NULL OR r_last.dock_id = $2)
       GROUP BY m.phone, mem.name, mem.email, r_last.name, r_last.status
       ORDER BY MAX(m.created_at) DESC`,
      [req.franchiseId, scope]
    );

    const phones = rows.map((r) => r.phone).filter(Boolean);
    let visiting = {};
    if (phones.length > 0) {
      const { rows: visits } = await db.query(
        `SELECT m.phone, f.id, f.name, f.slug
         FROM members m
         JOIN franchises f ON f.id = m.franchise_id
         WHERE m.phone = ANY($1::text[]) AND m.franchise_id <> $2`,
        [phones, req.franchiseId]
      );
      for (const v of visits) {
        (visiting[v.phone] = visiting[v.phone] || []).push({ id: v.id, name: v.name, slug: v.slug });
      }
    }

    res.json({
      conversations: rows.map((c) => ({ ...c, home_franchises: visiting[c.phone] || [] })),
    });
  } catch (err) {
    console.error("Conversations list error:", err);
    res.status(500).json({ error: "Database error" });
  }
});

app.get("/api/conversations/:phone", requireAuth, requireFranchiseContext, async (req, res) => {
  const phone = normalizePhone(req.params.phone);
  const scope = userDockScope(req);
  try {
    // Dock-scoped users only see this conversation if the most-recent matching
    // reservation in this franchise is at their dock.
    if (scope) {
      const { rows: r } = await db.query(
        `SELECT dock_id FROM reservations
          WHERE franchise_id = $1 AND phone = $2
          ORDER BY created_at DESC LIMIT 1`,
        [req.franchiseId, phone]
      );
      if (r.length === 0 || r[0].dock_id !== scope) {
        return res.status(404).json({ error: "Conversation not found" });
      }
    }
    const [{ rows: member }, { rows: messages }, { rows: reservations }, homeFranchises] = await Promise.all([
      db.query(`SELECT * FROM members WHERE franchise_id = $1 AND phone = $2`, [req.franchiseId, phone]),
      db.query(`SELECT * FROM messages WHERE franchise_id = $1 AND phone = $2 ORDER BY created_at ASC`, [req.franchiseId, phone]),
      db.query(
        `SELECT * FROM reservations WHERE franchise_id = $1 AND phone = $2 ORDER BY reservation_date DESC NULLS LAST`,
        [req.franchiseId, phone]
      ),
      findHomeFranchises(req.franchiseId, phone),
    ]);
    res.json({
      phone,
      member: member[0] || null,
      homeFranchises,
      messages: messages.map((m) => ({
        from: m.direction === "out" ? "system" : "member",
        text: m.body,
        time: m.created_at,
        reservationId: m.reservation_id,
        dockId: m.dock_id,
        twilioSid: m.twilio_sid,
        twilioStatus: m.twilio_status,
      })),
      reservations: reservations.map(rowToReservation),
    });
  } catch (err) {
    console.error("Conversation fetch error:", err);
    res.status(500).json({ error: "Database error" });
  }
});

// --- Web Push subscription endpoints ---
// The public VAPID key is fetched by the SPA so it can call subscribe() on the
// browser's PushManager.
app.get("/api/push/vapid-public-key", requireAuth, (req, res) => {
  if (!pushEnabled) return res.status(503).json({ error: "Push not configured" });
  res.json({ key: VAPID_PUBLIC_KEY });
});

app.post("/api/push/subscribe", requireAuth, requireFranchiseContext, async (req, res) => {
  if (!pushEnabled) return res.status(503).json({ error: "Push not configured" });
  const { endpoint, keys } = req.body || {};
  if (!endpoint || !keys || !keys.p256dh || !keys.auth) {
    return res.status(400).json({ error: "Invalid subscription" });
  }
  try {
    await db.query(
      `INSERT INTO push_subscriptions (user_id, franchise_id, endpoint, p256dh, auth, user_agent)
       VALUES ($1, $2, $3, $4, $5, $6)
       ON CONFLICT (endpoint) DO UPDATE
         SET user_id = EXCLUDED.user_id,
             franchise_id = EXCLUDED.franchise_id,
             p256dh = EXCLUDED.p256dh,
             auth = EXCLUDED.auth,
             user_agent = EXCLUDED.user_agent,
             last_seen_at = NOW()`,
      [req.session.userId, req.franchiseId, endpoint, keys.p256dh, keys.auth, req.headers["user-agent"] || null]
    );
    res.json({ success: true });
  } catch (err) {
    console.error("Push subscribe error:", err);
    res.status(500).json({ error: "Database error" });
  }
});

app.post("/api/push/unsubscribe", requireAuth, async (req, res) => {
  const { endpoint } = req.body || {};
  if (!endpoint) return res.status(400).json({ error: "endpoint required" });
  try {
    await db.query(`DELETE FROM push_subscriptions WHERE endpoint = $1 AND user_id = $2`,
      [endpoint, req.session.userId]);
    res.json({ success: true });
  } catch (err) {
    console.error("Push unsubscribe error:", err);
    res.status(500).json({ error: "Database error" });
  }
});

// --- Health ---
app.get("/api/health", (req, res) => {
  res.json({ status: "ok" });
});

// App version = short hash of the served frontend. The client polls this and
// reloads itself when it changes, so home-screen PWAs pick up new deploys
// without a manual refresh.
let APP_VERSION = "dev";
try {
  APP_VERSION = crypto.createHash("sha1")
    .update(require("fs").readFileSync(path.join(__dirname, "public", "index.html")))
    .digest("hex").slice(0, 12);
} catch (_) {}
app.get("/api/version", (req, res) => {
  res.set("Cache-Control", "no-store");
  res.json({ version: APP_VERSION });
});

// --- Salesforce time-sync (Mac cron pulls these, writes B25__Start__c) ---
// Authed by the shared hub-origin secret (same header the worker/SF pusher
// already use), not a user session — this is machine-to-machine.
function requireOriginSecret(req, res, next) {
  const secret = req.headers["x-origin-auth"];
  if (!hubOriginSecret || !secret || !safeEqual(secret, hubOriginSecret)) {
    return res.status(401).json({ error: "Unauthorized" });
  }
  next();
}

// Reservations whose start time changed via SMS and still need pushing to SF.
// Only rows with a real SF reservation id (source_id) are returned.
app.get("/api/sf-sync/pending", requireOriginSecret, async (req, res) => {
  try {
    const { rows } = await db.query(
      `SELECT id, source_id, reservation_date, return_time, name, dock_id
         FROM reservations
        WHERE needs_sf_push = TRUE
          AND source_id ~ '^[a-zA-Z0-9]{15,18}$'
        ORDER BY reservation_date ASC
        LIMIT 200`
    );
    res.json({ pending: rows });
  } catch (err) {
    console.error("sf-sync pending error:", err.message);
    res.status(500).json({ error: "Database error" });
  }
});

// --- On-demand date pull (any staff requests a date; Mac worker fulfils it) ---
// Open to managers and dock phones too so docks can send confirmations
// further ahead than tomorrow. Duplicate requests per date collapse below,
// and merge-mode imports mean a re-pull never resets statuses.
app.post("/api/reservations/pull", requireAuth, requireFranchiseContext, async (req, res) => {
  const date = String(req.body.date || "").trim();
  if (!/^\d{4}-\d{2}-\d{2}$/.test(date)) return res.status(400).json({ error: "Date must be YYYY-MM-DD" });
  try {
    // Collapse duplicate pending requests for the same date.
    const { rows } = await db.query(
      `INSERT INTO pull_requests (franchise_id, target_date, requested_by)
       SELECT $1, $2, $3
       WHERE NOT EXISTS (
         SELECT 1 FROM pull_requests
          WHERE franchise_id = $1 AND target_date = $2 AND status = 'pending'
       )
       RETURNING id`,
      [req.franchiseId, date, req.session.userId]
    );
    res.json({ success: true, queued: rows.length > 0, id: rows[0] ? rows[0].id : null, date });
  } catch (err) {
    console.error("pull request error:", err.message);
    res.status(500).json({ error: "Database error" });
  }
});

// Latest pull-request status for this franchise (the app polls this).
app.get("/api/reservations/pull/status", requireAuth, requireFranchiseContext, async (req, res) => {
  const { rows } = await db.query(
    `SELECT id, to_char(target_date, 'YYYY-MM-DD') AS target_date, status,
            result_count, error_detail, requested_at, completed_at
       FROM pull_requests WHERE franchise_id = $1
      ORDER BY id DESC LIMIT 1`, [req.franchiseId]
  );
  res.json({ latest: rows[0] || null });
});

// Mac worker: pending pulls + mark complete (machine auth).
app.get("/api/pull-requests/pending", requireOriginSecret, async (req, res) => {
  const { rows } = await db.query(
    `SELECT id, franchise_id, to_char(target_date, 'YYYY-MM-DD') AS target_date
       FROM pull_requests WHERE status = 'pending' ORDER BY id ASC LIMIT 20`
  );
  res.json({ pending: rows });
});
app.post("/api/pull-requests/complete", requireOriginSecret, async (req, res) => {
  const { id, status, count, error } = req.body || {};
  if (!id) return res.status(400).json({ error: "Missing id" });
  try {
    await db.query(
      `UPDATE pull_requests
          SET status = $1, result_count = $2, error_detail = $3, completed_at = NOW()
        WHERE id = $4`,
      [status === "error" ? "error" : "done", Number.isInteger(count) ? count : null, error || null, id]
    );
    res.json({ success: true });
  } catch (err) {
    console.error("pull complete error:", err.message);
    res.status(500).json({ error: "Database error" });
  }
});

// Clear the flag for rows the Mac successfully pushed to SF.
app.post("/api/sf-sync/ack", requireOriginSecret, async (req, res) => {
  const ids = Array.isArray(req.body.ids) ? req.body.ids.filter((x) => typeof x === "string") : [];
  if (ids.length === 0) return res.json({ cleared: 0 });
  try {
    const { rowCount } = await db.query(
      `UPDATE reservations SET needs_sf_push = FALSE WHERE id = ANY($1::text[])`, [ids]
    );
    res.json({ cleared: rowCount });
  } catch (err) {
    console.error("sf-sync ack error:", err.message);
    res.status(500).json({ error: "Database error" });
  }
});

// Recovery tool: rows that were wrongly auto-cancelled (e.g. because the SF
// feed once omitted On The Water / Completed trips) get their status
// recomputed from their own SMS history. Body: { items: [{sourceId, sfStatus}] }.
// Only rows currently 'cancelled' whose SF status is still active are touched;
// a member who genuinely texted a cancel reply stays cancelled.
app.post("/api/sf-sync/repair-cancelled", requireOriginSecret, async (req, res) => {
  const items = Array.isArray(req.body.items) ? req.body.items : [];
  const activeIds = items
    .filter((x) => x && typeof x.sourceId === "string" && !/^cancel/i.test(String(x.sfStatus || "")))
    .map((x) => x.sourceId);
  if (activeIds.length === 0) return res.json({ repaired: [] });

  const cancelRe = /(^|\s)(cancel|cancelled|nope|nah|cant make it|can not make it|cannot make it|wont be there|not coming|count me out|need to cancel|want to cancel|have to cancel|please cancel)(\s|$)|^(no|n)$/;
  const confirmRe = /(^|\s)(confirm|confirmed|yes|yep|yeah|yup|sounds good|okay|absolutely|perfect|see you (there|soon|then)|will be there|looking forward|count me in|all good|good to go)(\s|$)|^(y|c|ok|sure|good|great)$/;

  try {
    const { rows } = await db.query(
      `SELECT id, franchise_id, phone, name, status, message_sent, time_updated
       FROM reservations WHERE status = 'cancelled' AND source_id = ANY($1::text[])`,
      [activeIds]
    );
    const repaired = [];
    for (const r of rows) {
      let newStatus = null;
      if (r.time_updated) {
        newStatus = "confirmed";
      } else if (r.phone) {
        const { rows: inbound } = await db.query(
          `SELECT body FROM messages
           WHERE franchise_id = $1 AND phone = $2 AND direction = 'in'
           ORDER BY created_at ASC`,
          [r.franchise_id, r.phone]
        );
        for (const m of inbound) {
          const t = String(m.body || "").toLowerCase().replace(/[^a-z0-9\s:]/g, "").trim();
          if (cancelRe.test(t)) newStatus = "cancelled";
          else if (confirmRe.test(t)) newStatus = "confirmed";
        }
      }
      if (!newStatus) newStatus = r.message_sent ? "pending" : "unconfirmed";
      if (newStatus !== "cancelled") {
        await db.query(
          `UPDATE reservations SET status = $1 WHERE id = $2`,
          [newStatus, r.id]
        );
        repaired.push({ id: r.id, name: r.name, status: newStatus });
      }
    }
    res.json({ repaired, checked: rows.length });
  } catch (err) {
    console.error("repair-cancelled error:", err.message);
    res.status(500).json({ error: "Database error" });
  }
});

// --- Confirmation message template (admins edit, everyone's sends use it) ---
app.get("/api/message-template", requireAuth, requireFranchiseContext, (req, res) => {
  res.json({
    template: req.franchise.message_template || DEFAULT_MESSAGE_TEMPLATE,
    isCustom: !!req.franchise.message_template,
    default: DEFAULT_MESSAGE_TEMPLATE,
    placeholders: TEMPLATE_PLACEHOLDERS,
  });
});

// Live preview — renders the supplied (unsaved) template against a sample
// reservation so the editor can show what a member would receive.
app.post("/api/message-template/preview", requireAuth, requireFranchiseContext, (req, res) => {
  const template = String(req.body.template || DEFAULT_MESSAGE_TEMPLATE).slice(0, 1200);
  const sample = {
    name: "Jordan Rivera", service: "SeaRay 230", dock_id: (req.franchise.docks[0] || {}).id,
    reservation_date: new Date(Date.now() + 2 * 86400000).setHours(8, 0, 0, 0),
    return_time: new Date(Date.now() + 2 * 86400000).setHours(13, 0, 0, 0),
    sf_timeframe: "Fall Weekday - Morning",
  };
  res.json({ preview: renderTemplate(template, templateValues(sample, req.franchise)) });
});

app.post("/api/message-template", requireAuth, requireFranchiseContext, async (req, res) => {
  if (req.session.role !== "super_admin" && req.session.role !== "franchise_admin") {
    return res.status(403).json({ error: "Only admins can edit the message template" });
  }
  let template = req.body.template;
  // Empty / reset → fall back to the built-in default (store NULL).
  if (template != null) template = String(template).slice(0, 1200).trim();
  const toStore = template ? template : null;
  await db.query(`UPDATE franchises SET message_template = $1 WHERE id = $2`, [toStore, req.franchiseId]);
  invalidateFranchise(req.franchiseId);
  res.json({ success: true, template: toStore || DEFAULT_MESSAGE_TEMPLATE, isCustom: !!toStore });
});

// --- Voice: forward incoming calls to the club's main line ---
// The SMS number looks like a normal number, so members will call it. Rather
// than let the call die, forward it to the franchise's voice_forward_number
// (falls back to the VOICE_FORWARD env var). Twilio hits this for both GET
// and POST depending on how the number's voice webhook is configured.
async function handleVoice(req, res) {
  const to = req.body.To || req.query.To;
  let forwardTo = process.env.VOICE_FORWARD || "";
  try {
    const franchise = to ? await findFranchiseByInboundTo(to) : null;
    if (franchise && franchise.voice_forward_number) forwardTo = franchise.voice_forward_number;
  } catch (err) {
    console.error("Voice lookup error:", err.message);
  }
  res.set("Content-Type", "text/xml");
  if (forwardTo) {
    res.send(`<?xml version="1.0" encoding="UTF-8"?><Response><Dial>${forwardTo}</Dial></Response>`);
  } else {
    res.send(`<?xml version="1.0" encoding="UTF-8"?><Response><Say>This number is for text messages only. Please call your Freedom Boat Club location directly. Goodbye.</Say><Hangup/></Response>`);
  }
}
app.post("/api/voice", express.urlencoded({ extended: false }), handleVoice);
app.get("/api/voice", handleVoice);

// --- Root + static ---
app.get("/", (req, res) => res.sendFile(path.join(__dirname, "public", "index.html")));
app.use(express.static(path.join(__dirname, "public")));
app.get("/dashboard", (req, res) => res.sendFile(path.join(__dirname, "public", "index.html")));

// --- Start ---
async function start() {
  try {
    await db.initSchema();
  } catch (err) {
    console.error("Schema init failed:", err.message);
    if (isProduction) process.exit(1);
  }
  app.listen(PORT, () => {
    console.log(`\nReservation SMS (multi-tenant) running on port ${PORT}`);
    console.log(`   Health check: http://localhost:${PORT}/api/health`);
  });
}

start();
