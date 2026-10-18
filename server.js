// Key server v2 - ký phản hồi ECDSA P-256, lưu trữ bền vững (Upstash Redis) hoặc file.
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
const R_URL = process.env.UPSTASH_REDIS_REST_URL;
const R_TOKEN = process.env.UPSTASH_REDIS_REST_TOKEN;
const R_KEY = "qd_state";
const DAY = 86400000;

// ---------- Khóa ký ----------
// SIGN_PRIVATE_KEY chấp nhận: base64 của PEM | PEM thường (có thể viết \n) | base64 DER (PKCS8/SEC1) | hex 32 byte.
const b64url = (b) => Buffer.from(b).toString("base64").replace(/\+/g, "-").replace(/\//g, "_").replace(/=+$/, "");

function parseSignKey(raw) {
  raw = String(raw).trim().replace(/^["']|["']$/g, "");
  const attempts = [
    () => { if (!raw.includes("BEGIN")) throw 0; return crypto.createPrivateKey(raw.replace(/\\n/g, "\n")); },
    () => { const t = Buffer.from(raw, "base64").toString("utf8"); if (!t.includes("BEGIN")) throw 0; return crypto.createPrivateKey(t); },
    () => crypto.createPrivateKey({ key: Buffer.from(raw, "base64"), format: "der", type: "pkcs8" }),
    () => crypto.createPrivateKey({ key: Buffer.from(raw, "base64"), format: "der", type: "sec1" }),
    () => {
      if (!/^[0-9a-fA-F]{64}$/.test(raw)) throw 0;
      const d = Buffer.from(raw, "hex");
      const e = crypto.createECDH("prime256v1"); e.setPrivateKey(d);
      const pub = e.getPublicKey();
      return crypto.createPrivateKey({ key: { kty: "EC", crv: "P-256", d: b64url(d), x: b64url(pub.subarray(1, 33)), y: b64url(pub.subarray(33, 65)) }, format: "jwk" });
    },
  ];
  for (const f of attempts) {
    try {
      const k = f();
      if (k.asymmetricKeyType === "ec" && k.asymmetricKeyDetails.namedCurve === "prime256v1") return k;
    } catch (_) {}
  }
  throw new Error("không đọc được khóa (cần ECDSA P-256)");
}

// Khóa công khai 65 byte (X9.63) dạng base64: dán vào kPubB64 trong app
function publicB64(k) {
  const der = crypto.createPublicKey(k).export({ type: "spki", format: "der" });
  return der.subarray(der.length - 65).toString("base64");
}

let SIGN_KEY = null, SIGN_PUB = null;
if (process.env.SIGN_PRIVATE_KEY) {
  try {
    SIGN_KEY = parseSignKey(process.env.SIGN_PRIVATE_KEY);
    SIGN_PUB = publicB64(SIGN_KEY);
    const t = Buffer.from("test");
    const ok = crypto.verify("sha256", t, crypto.createPublicKey(SIGN_KEY), crypto.sign("sha256", t, SIGN_KEY));
    if (!ok) throw new Error("tự kiểm tra chữ ký thất bại");
    console.log("Khóa ký OK. Khóa công khai (kPubB64 trong app):", SIGN_PUB);
  } catch (e) {
    SIGN_KEY = null; SIGN_PUB = null;
    console.error("SIGN_PRIVATE_KEY không hợp lệ:", e.message);
  }
} else {
  console.warn("Chưa có SIGN_PRIVATE_KEY: phản hồi sẽ không được ký, app sẽ từ chối (lỗi E2).");
}

// ---------- Lưu trữ ----------
async function redis(cmd) {
  const r = await fetch(R_URL, { method: "POST", headers: { Authorization: "Bearer " + R_TOKEN }, body: JSON.stringify(cmd) });
  const j = await r.json();
  if (j.error) throw new Error(j.error);
  return j.result;
}
async function persist() {
  const data = JSON.stringify(state);
  if (R_URL) return redis(["SET", R_KEY, data]);
  fs.mkdirSync(DATA_DIR, { recursive: true });
  const tmp = STATE_FILE + ".tmp";
  fs.writeFileSync(tmp, data);
  fs.renameSync(tmp, STATE_FILE); // ghi nguyên tử, không hỏng file khi bị tắt giữa chừng
}
let chain = Promise.resolve();
function save() {
  chain = chain.then(persist).catch((e) => console.error("Lưu lỗi:", e.message));
  return chain;
}

// state = { keys: { KEY: {createdAt, durationMs, device, activatedAt, expiresAt, revoked, note} }, imported }
let state = { keys: {}, imported: false };
const newKey = (durationMs, note) => ({ createdAt: Date.now(), durationMs, device: null, activatedAt: null, expiresAt: null, revoked: false, note: note || "" });

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
      state.keys[k] = { ...newKey(DEFAULT_DAYS * DAY), device: v.device || null, activatedAt: v.activatedAt || null,
        expiresAt: v.expiresAt || null, revoked: !!v.revoked, createdAt: v.activatedAt || Date.now() };
    }
  }
  if (!state.imported) { // nạp keys.txt một lần (nếu có file)
    try {
      fs.readFileSync(path.join(__dirname, "keys.txt"), "utf8").split(/\r?\n/)
        .map((s) => s.trim().toUpperCase()).filter(Boolean).forEach((k) => {
          if (!state.keys[k]) state.keys[k] = newKey(DEFAULT_DAYS * DAY);
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
app.set("trust proxy", 1); // chạy sau proxy của Render: nếu thiếu, mọi người dùng chung 1 IP và bị giới hạn chung
app.disable("x-powered-by");
app.use(express.json({ limit: "20kb" }));

const limited = (max) => rateLimit({
  windowMs: 60_000, max, standardHeaders: true, legacyHeaders: false,
  handler: (req, res) => res.status(429).json({ ok: false, error: "rate_limited" }),
});
app.use("/api", limited(60));
app.use("/admin/api", limited(120));

app.get("/", (_, res) => res.send("ok"));
app.get("/health", (_, res) => res.json({
  status: "ok", keys: Object.keys(state.keys).length, persistent: !!R_URL, signing: !!SIGN_KEY, pub: SIGN_PUB,
}));

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
  const key = String(b.key || "").trim().toUpperCase().slice(0, 80);
  const device = String(b.device_id || "").trim().slice(0, 80);
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
const adminFail = rateLimit({ // chống dò mật khẩu admin: tối đa 15 lần sai mỗi phút
  windowMs: 60_000, max: 15, skipSuccessfulRequests: true, standardHeaders: false, legacyHeaders: false,
  handler: (req, res) => res.status(429).json({ error: "too_many_attempts" }),
});
function admin(req, res, next) {
  const given = crypto.createHash("sha256").update(String(req.get("x-admin-key") || "")).digest();
  const want = crypto.createHash("sha256").update(ADMIN_KEY).digest();
  if (!ADMIN_KEY || !crypto.timingSafeEqual(given, want)) return res.status(401).json({ error: "unauthorized" });
  next();
}
const adminGuard = [adminFail, admin];

app.get("/admin", (_, res) => {
  res.set("Cache-Control", "no-store");
  res.sendFile(path.join(__dirname, "admin.html"));
});

app.get("/admin/api/keys", adminGuard, (_, res) => {
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

app.post("/admin/api/keys", adminGuard, (req, res) => {
  const b = req.body || {};
  const durationMs = Math.max(0, Math.min(Number(b.durationMs) || 0, 3650 * DAY));
  const note = String(b.note || "").slice(0, 80);
  const created = [], skipped = [];
  const add = (k) => {
    if (state.keys[k]) { skipped.push(k); return false; }
    state.keys[k] = newKey(durationMs, note);
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
app.post("/admin/api/keys/:key/revoke", adminGuard, (req, res) => withKey(req, res, (k, s) => { s.revoked = true; }));
app.post("/admin/api/keys/:key/restore", adminGuard, (req, res) => withKey(req, res, (k, s) => { s.revoked = false; }));
// mode "device": chỉ gỡ máy, giữ nguyên hạn. mode "full": về trạng thái chưa dùng, hạn tính lại từ lần kích hoạt tiếp theo
app.post("/admin/api/keys/:key/reset", adminGuard, (req, res) => withKey(req, res, (k, s) => {
  s.device = null;
  if ((req.body || {}).mode === "full") { s.activatedAt = null; s.expiresAt = null; }
}));
app.delete("/admin/api/keys/:key", adminGuard, (req, res) => withKey(req, res, (k) => { delete state.keys[k]; }));

app.use((err, req, res, next) => res.status(400).json({ ok: false, error: "bad_request" })); // JSON hỏng

loadState().then(() => {
  app.listen(PORT, () => console.log("Key server chạy tại cổng " + PORT + (R_URL ? " (Redis)" : " (file, KHÔNG bền vững trên gói free)")));
});
