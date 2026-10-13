const express = require("express");
const rateLimit = require("express-rate-limit");
const crypto = require("crypto");
const fs = require("fs");
const path = require("path");

const PORT = process.env.PORT || 3000;
const ADMIN_KEY = process.env.ADMIN_KEY || "";
const DEFAULT_DAYS = parseInt(process.env.KEY_DURATION_DAYS || "0", 10); // hạn cho key import từ keys.txt (0 = vĩnh viễn)
const DATA_DIR = process.env.DATA_DIR || path.join(__dirname, "data");
const STATE_FILE = path.join(DATA_DIR, "state.json");
const R_URL = process.env.UPSTASH_REDIS_REST_URL;   // tùy chọn: lưu dữ liệu bền vững
const R_TOKEN = process.env.UPSTASH_REDIS_REST_TOKEN;
const R_KEY = "qd_state";
const DAY = 86400000;

// Khóa riêng để ký phản hồi (base64 của PEM). Đặt trong biến môi trường SIGN_PRIVATE_KEY trên Render.
let SIGN_KEY = null;
if (process.env.SIGN_PRIVATE_KEY) {
  try { SIGN_KEY = crypto.createPrivateKey(Buffer.from(process.env.SIGN_PRIVATE_KEY, "base64").toString()); }
  catch (e) { console.error("SIGN_PRIVATE_KEY không hợp lệ:", e.message); }
} else console.warn("Chưa có SIGN_PRIVATE_KEY: phản hồi sẽ không được ký, dylib mới sẽ từ chối.");

// ---------- Lưu trữ ----------
async function redis(cmd) {
  const r = await fetch(R_URL, {
    method: "POST",
    headers: { Authorization: "Bearer " + R_TOKEN },
    body: JSON.stringify(cmd),
  });
  const j = await r.json();
  if (j.error) throw new Error(j.error);
  return j.result;
}
async function persist() {
  const data = JSON.stringify(state);
  if (R_URL) return redis(["SET", R_KEY, data]);
  fs.mkdirSync(DATA_DIR, { recursive: true });
  fs.writeFileSync(STATE_FILE, data);
}
let chain = Promise.resolve();
function save() {
  chain = chain.then(persist).catch((e) => console.error("Lưu lỗi:", e.message));
  return chain;
}

// state = { keys: { KEY: {createdAt, durationMs, device, activatedAt, expiresAt, revoked, note} }, imported }
let state = { keys: {}, imported: false };

async function loadState() {
  let raw = null;
  try {
    if (R_URL) { const s = await redis(["GET", R_KEY]); raw = s ? JSON.parse(s) : null; }
    else raw = JSON.parse(fs.readFileSync(STATE_FILE, "utf8"));
  } catch (e) {
    if (R_URL) { console.error("Không đọc được Redis:", e.message); process.exit(1); }
  }
  if (raw && raw.keys) state = raw;
  else if (raw) { // định dạng cũ
    for (const [k, v] of Object.entries(raw)) {
      state.keys[k] = { createdAt: v.activatedAt || Date.now(), durationMs: DEFAULT_DAYS * DAY,
        device: v.device || null, activatedAt: v.activatedAt || null, expiresAt: v.expiresAt || null,
        revoked: !!v.revoked, note: "" };
    }
  }
  if (!state.imported) { // nạp keys.txt một lần
    try {
      fs.readFileSync(path.join(__dirname, "keys.txt"), "utf8").split(/\r?\n/)
        .map((s) => s.trim().toUpperCase()).filter(Boolean).forEach((k) => {
          if (!state.keys[k]) state.keys[k] = { createdAt: Date.now(), durationMs: DEFAULT_DAYS * DAY,
            device: null, activatedAt: null, expiresAt: null, revoked: false, note: "" };
        });
    } catch (_) {}
    state.imported = true;
    await persist();
  }
}

function statusOf(s, now) {
  if (s.revoked) return "revoked";
  if (!s.activatedAt) return "unused";
  if (s.expiresAt && now > s.expiresAt) return "expired";
  return "active";
}

// ---------- App ----------
const app = express();
app.use(express.json({ limit: "100kb" }));
app.use("/api", rateLimit({ windowMs: 60_000, max: 30, standardHeaders: true, legacyHeaders: false }));
app.use("/admin/api", rateLimit({ windowMs: 60_000, max: 120, standardHeaders: true, legacyHeaders: false }));

app.get("/", (_, res) => res.send("ok"));
app.get("/health", (_, res) => res.json({ status: "ok", keys: Object.keys(state.keys).length, persistent: !!R_URL, signing: !!SIGN_KEY }));

// Trả lời có chữ ký: ok|error|expires_at|server_time|nonce|key|device
function reply(res, code, p, key, device, nonce) {
  const t = Date.now();
  const body = { ...p, server_time: t, nonce };
  const msg = [body.ok ? 1 : 0, body.error || "", body.expires_at || 0, t, nonce, key, device].join("|");
  if (SIGN_KEY) body.sig = crypto.sign("sha256", Buffer.from(msg), SIGN_KEY).toString("base64");
  res.status(code).json(body);
}

// Kích hoạt / kiểm tra. Body: { key, device_id, nonce }
function check(req, res) {
  const b = req.body || {};
  const key = String(b.key || "").trim().toUpperCase();
  const device = String(b.device_id || "").trim();
  const nonce = String(b.nonce || "").slice(0, 64);
  if (!key || !device || !nonce) return res.status(400).json({ ok: false, error: "missing_params" });
  const R = (code, p) => reply(res, code, p, key, device, nonce);
  const s = state.keys[key];
  if (!s) return R(404, { ok: false, error: "invalid_key" });
  if (s.revoked) return R(403, { ok: false, error: "revoked" });
  const now = Date.now();
  if (s.activatedAt && s.expiresAt && now > s.expiresAt) return R(403, { ok: false, error: "expired" });
  if (s.device && s.device !== device) return R(403, { ok: false, error: "device_mismatch" });
  let dirty = false;
  if (!s.device) { s.device = device; dirty = true; }
  if (!s.activatedAt) {
    s.activatedAt = now;
    s.expiresAt = s.durationMs > 0 ? now + s.durationMs : null;
    dirty = true;
  }
  if (dirty) save();
  R(200, { ok: true, expires_at: s.expiresAt });
}
app.post("/api/activate", check);
app.post("/api/verify", check);

// ---------- Admin ----------
function admin(req, res, next) {
  const given = Buffer.from(String(req.get("x-admin-key") || ""));
  const want = Buffer.from(ADMIN_KEY);
  if (!ADMIN_KEY || given.length !== want.length || !crypto.timingSafeEqual(given, want))
    return res.status(401).json({ error: "unauthorized" });
  next();
}

app.get("/admin", (_, res) => {
  res.set("Cache-Control", "no-store");
  res.sendFile(path.join(__dirname, "admin.html"));
});

app.get("/admin/api/keys", admin, (_, res) => {
  const now = Date.now();
  const stats = { total: 0, unused: 0, active: 0, expired: 0, revoked: 0 };
  const keys = Object.entries(state.keys).map(([key, s]) => {
    const status = statusOf(s, now);
    stats.total++; stats[status]++;
    return { key, status, device: s.device, note: s.note || "", createdAt: s.createdAt,
      durationMs: s.durationMs || 0, activatedAt: s.activatedAt, expiresAt: s.expiresAt };
  });
  res.json({ now, stats, keys });
});

const ALPHA = "ABCDEFGHJKLMNPQRSTUVWXYZ0123456789";
function rnd(n) {
  const b = crypto.randomBytes(n); let s = "";
  for (let i = 0; i < n; i++) s += ALPHA[b[i] % ALPHA.length];
  return s;
}

app.post("/admin/api/keys", admin, (req, res) => {
  const b = req.body || {};
  const durationMs = Math.max(0, Math.min(Number(b.durationMs) || 0, 3650 * DAY));
  const note = String(b.note || "").slice(0, 80);
  const created = [], skipped = [];
  const add = (k) => {
    if (state.keys[k]) { skipped.push(k); return false; }
    state.keys[k] = { createdAt: Date.now(), durationMs, device: null, activatedAt: null,
      expiresAt: null, revoked: false, note };
    created.push(k); return true;
  };
  if (Array.isArray(b.custom) && b.custom.length) {
    for (const raw of b.custom.slice(0, 500)) {
      const k = String(raw).trim().toUpperCase();
      if (!/^[A-Z0-9][A-Z0-9_-]{3,60}$/.test(k)) { skipped.push(k); continue; }
      add(k);
    }
  } else {
    const count = Math.min(Math.max(parseInt(b.count) || 1, 1), 200);
    const prefix = String(b.prefix || "QDONENLITE").toUpperCase().replace(/[^A-Z0-9]/g, "").slice(0, 20) || "QDONENLITE";
    let guard = 0;
    while (created.length < count && guard++ < count * 20) add(`${prefix}-${rnd(3)}-${rnd(4)}-${rnd(3)}`);
  }
  save();
  res.json({ ok: true, created, skipped });
});

function withKey(req, res, fn) {
  const k = String(req.params.key || "").toUpperCase();
  const s = state.keys[k];
  if (!s) return res.status(404).json({ error: "invalid_key" });
  fn(k, s);
  save();
  res.json({ ok: true });
}
app.post("/admin/api/keys/:key/revoke", admin, (req, res) => withKey(req, res, (k, s) => { s.revoked = true; }));
app.post("/admin/api/keys/:key/restore", admin, (req, res) => withKey(req, res, (k, s) => { s.revoked = false; }));
// mode "device": chỉ gỡ máy, giữ nguyên hạn. mode "full": về trạng thái chưa dùng, hạn tính lại từ lần kích hoạt tiếp theo
app.post("/admin/api/keys/:key/reset", admin, (req, res) => withKey(req, res, (k, s) => {
  s.device = null;
  if ((req.body || {}).mode === "full") { s.activatedAt = null; s.expiresAt = null; }
}));
app.delete("/admin/api/keys/:key", admin, (req, res) => withKey(req, res, (k) => { delete state.keys[k]; }));

loadState().then(() => {
  app.listen(PORT, () => console.log("Key server chạy tại cổng " + PORT + (R_URL ? " (Redis)" : " (file, không bền vững trên gói free)")));
});
