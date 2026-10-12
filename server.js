const express = require("express");
const rateLimit = require("express-rate-limit");
const fs = require("fs");
const path = require("path");

const PORT = process.env.PORT || 3000;
const ADMIN_KEY = process.env.ADMIN_KEY || "";
const DURATION_DAYS = parseInt(process.env.KEY_DURATION_DAYS || "0", 10); // 0 = vĩnh viễn
const DATA_DIR = process.env.DATA_DIR || path.join(__dirname, "data");
const STATE_FILE = path.join(DATA_DIR, "state.json");

fs.mkdirSync(DATA_DIR, { recursive: true });

// Danh sách key hợp lệ
const validKeys = new Set(
  fs.readFileSync(path.join(__dirname, "keys.txt"), "utf8")
    .split(/\r?\n/).map(s => s.trim().toUpperCase()).filter(Boolean)
);

// Trạng thái: { KEY: { device, activatedAt, expiresAt, revoked } }
let state = {};
try { state = JSON.parse(fs.readFileSync(STATE_FILE, "utf8")); } catch (_) {}
const save = () => fs.writeFileSync(STATE_FILE, JSON.stringify(state, null, 2));

const app = express();
app.use(express.json({ limit: "10kb" }));
app.use(rateLimit({ windowMs: 60_000, max: 30, standardHeaders: true, legacyHeaders: false }));

app.get("/", (_, res) => res.send("ok"));
app.get("/health", (_, res) => res.json({ status: "ok", keys: validKeys.size }));

// Kích hoạt / kiểm tra key. Body: { "key": "...", "device_id": "..." }
function check(req, res) {
  const key = String(req.body.key || "").trim().toUpperCase();
  const device = String(req.body.device_id || "").trim();
  if (!key || !device) return res.status(400).json({ ok: false, error: "missing_params" });
  if (!validKeys.has(key)) return res.status(404).json({ ok: false, error: "invalid_key" });

  const now = Date.now();
  let s = state[key];

  if (!s) {
    s = state[key] = {
      device,
      activatedAt: now,
      expiresAt: DURATION_DAYS > 0 ? now + DURATION_DAYS * 86400000 : null,
      revoked: false,
    };
    save();
  }
  if (s.revoked) return res.status(403).json({ ok: false, error: "revoked" });
  if (s.device !== device) return res.status(403).json({ ok: false, error: "device_mismatch" });
  if (s.expiresAt && now > s.expiresAt) return res.status(403).json({ ok: false, error: "expired" });

  res.json({ ok: true, expires_at: s.expiresAt });
}
app.post("/api/activate", check);
app.post("/api/verify", check);

// ---- Admin (header: x-admin-key) ----
function admin(req, res, next) {
  if (!ADMIN_KEY || req.get("x-admin-key") !== ADMIN_KEY)
    return res.status(401).json({ error: "unauthorized" });
  next();
}
app.get("/admin/stats", admin, (_, res) => {
  const used = Object.keys(state).length;
  res.json({ total: validKeys.size, used, unused: validKeys.size - used });
});
app.get("/admin/key/:key", admin, (req, res) => {
  const k = req.params.key.toUpperCase();
  if (!validKeys.has(k)) return res.status(404).json({ error: "invalid_key" });
  res.json(state[k] || { unused: true });
});
app.post("/admin/reset/:key", admin, (req, res) => { // gỡ liên kết thiết bị
  const k = req.params.key.toUpperCase();
  delete state[k]; save(); res.json({ ok: true });
});
app.post("/admin/revoke/:key", admin, (req, res) => {
  const k = req.params.key.toUpperCase();
  if (!validKeys.has(k)) return res.status(404).json({ error: "invalid_key" });
  state[k] = { ...(state[k] || {}), revoked: true }; save(); res.json({ ok: true });
});

app.listen(PORT, () => console.log("Key server chạy tại cổng " + PORT));
