/**
 * SZERVER OLDAL - IP korlátozás, Szerkeszthető jelszavak, Név alapú belépés
 */
require('dotenv').config();
const express = require('express');
const mongoose = require('mongoose');
const jwt = require('jsonwebtoken');
const crypto = require('crypto');
const otplib = require('otplib');
const cors = require('cors');
const path = require('path');

const app = express();
app.set('trust proxy', true); // Fontos az IP címek pontos lekéréséhez (pl. Heroku/Cloudflare alatt)
app.use(express.json());
app.use(cors());

// --- KONFIGURÁCIÓ ---
const PORT = process.env.PORT || 5000;
const MONGO_URI = process.env.MONGO_URI || 'mongodb://127.0.0.1:27017/authenticator_db';
const JWT_SECRET = process.env.JWT_SECRET || 'titkos-kulcs-123';
const MASTER_PASSWORD = process.env.MASTER_PASSWORD || 'admin123';

app.use(express.static(path.join(__dirname, 'public')));

// --- ADATBÁZIS MODELLEK ---
const KeySchema = new mongoose.Schema({
  name: { type: String, required: true },
  secret: { type: String, required: true },
  createdAt: { type: Date, default: Date.now }
});

const ShareSchema = new mongoose.Schema({
  keyId: { type: mongoose.Schema.Types.ObjectId, ref: 'Key', required: true },
  label: { type: String, required: true },     // Ezt kell megadnia a vendégnek névként
  password: { type: String, required: true },  // Admin látja és módosíthatja
  shareToken: { type: String, required: true, unique: true },
  allowedIp: { type: String, default: null },  // Az első IP, ami rögzül
  sessionStartedAt: { type: Date, default: null },
  createdAt: { type: Date, default: Date.now }
});

const Key = mongoose.model('Key', KeySchema);
const Share = mongoose.model('Share', ShareSchema);

// --- HITELLESÍTÉS ---
const isOwner = (req, res, next) => {
  const token = req.headers['authorization'];
  if (!token) return res.status(401).json({ error: 'Nincs bejelentkezve' });
  try {
    const decoded = jwt.verify(token, JWT_SECRET);
    req.user = decoded;
    next();
  } catch (e) {
    res.status(401).json({ error: 'Érvénytelen munkamenet' });
  }
};

// --- API ÚTVONALAK ---

// Admin Login
app.post('/api/login', (req, res) => {
  const { password } = req.body;
  if (password === MASTER_PASSWORD) {
    const token = jwt.sign({ role: 'owner' }, JWT_SECRET, { expiresIn: '7d' });
    return res.json({ token });
  }
  res.status(401).json({ error: 'Hibás mesterjelszó!' });
});

// Kulcsok kezelése
app.get('/api/keys', isOwner, async (req, res) => {
  const keys = await Key.find();
  const result = keys.map(k => ({
    id: k._id, name: k.name,
    code: otplib.authenticator.generate(k.secret),
    remaining: otplib.authenticator.timeRemaining()
  }));
  res.json(result);
});

app.post('/api/keys', isOwner, async (req, res) => {
  const { name, secret } = req.body;
  const newKey = new Key({ name, secret: secret.replace(/\s/g, '').toUpperCase() });
  await newKey.save();
  res.json(newKey);
});

app.delete('/api/keys/:id', isOwner, async (req, res) => {
  await Key.findByIdAndDelete(req.params.id);
  await Share.deleteMany({ keyId: req.params.id });
  res.json({ success: true });
});

// Megosztások kezelése
app.post('/api/shares', isOwner, async (req, res) => {
  const { keyId, label, customPassword } = req.body;
  const password = customPassword || crypto.randomBytes(4).toString('hex');
  const shareToken = crypto.randomBytes(16).toString('hex');
  const share = new Share({ keyId, label, password, shareToken });
  await share.save();
  res.json(share);
});

app.get('/api/shares', isOwner, async (req, res) => {
  const shares = await Share.find().populate('keyId', 'name');
  res.json(shares);
});

app.patch('/api/shares/:id', isOwner, async (req, res) => {
  const { password, allowedIp } = req.body;
  await Share.findByIdAndUpdate(req.params.id, { password, allowedIp });
  res.json({ success: true });
});

app.delete('/api/shares/:id', isOwner, async (req, res) => {
  await Share.findByIdAndDelete(req.params.id);
  res.json({ success: true });
});

// --- VENDÉG KÓD LEKÉRÉS (IP ÉS NÉV ELLENŐRZÉSSEL) ---
app.post('/api/public/code', async (req, res) => {
  const { token, label, password } = req.body;
  const clientIp = req.ip || req.headers['x-forwarded-for'] || req.socket.remoteAddress;

  const share = await Share.findOne({ shareToken: token }).populate('keyId');
  
  if (!share) return res.status(404).json({ error: 'Érvénytelen link' });

  // 1. Név és Jelszó ellenőrzése
  if (share.label !== label || share.password !== password) {
    return res.status(401).json({ error: 'Hibás név vagy jelszó' });
  }

  // 2. IP Cím ellenőrzése / Rögzítése
  if (!share.allowedIp) {
    share.allowedIp = clientIp; // Első használatkor rögzítjük
    await share.save();
  } else if (share.allowedIp !== clientIp) {
    return res.status(403).json({ error: 'Ez a link le van védve egy másik IP címre!' });
  }

  // 3. Napi 1 perces korlát
  const now = new Date();
  const ONE_MINUTE = 60 * 1000;
  const TWENTY_FOUR_HOURS = 24 * 60 * 60 * 1000;

  if (!share.sessionStartedAt || (now - share.sessionStartedAt) >= TWENTY_FOUR_HOURS) {
    share.sessionStartedAt = now;
    await share.save();
  }

  const elapsed = now - share.sessionStartedAt;
  if (elapsed > ONE_MINUTE) {
    return res.status(403).json({ error: 'A mai 1 perces kereted elfogyott.' });
  }

  res.json({
    name: share.keyId.name,
    code: otplib.authenticator.generate(share.keyId.secret),
    remaining: otplib.authenticator.timeRemaining(),
    sessionExpiresIn: Math.max(0, Math.floor((ONE_MINUTE - elapsed) / 1000))
  });
});

app.get('*', (req, res) => {
  res.sendFile(path.join(__dirname, 'public', 'index.html'));
});

mongoose.connect(MONGO_URI).then(() => {
  app.listen(PORT, () => console.log(`Szerver fut a ${PORT} porton.`));
});
