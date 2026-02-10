/**
 * SZERVER OLDAL (Backend) - Frissítve 1 perces lejárati idővel
 */
require('dotenv').config();
const express = require('express');
const mongoose = require('mongoose');
const bcrypt = require('bcryptjs');
const jwt = require('jsonwebtoken');
const crypto = require('crypto');
const otplib = require('otplib');
const cors = require('cors');
const path = require('path');

const app = express();

app.use(express.json());
app.use(cors());

// --- KONFIGURÁCIÓ ---
const PORT = process.env.PORT || 5000;
const MONGO_URI = process.env.MONGO_URI || 'mongodb://127.0.0.1:27017/authenticator_db';
const JWT_SECRET = process.env.JWT_SECRET || 'titkos-kulcs-a-tokenekhez';
const MASTER_PASSWORD = process.env.MASTER_PASSWORD || 'admin123';
const MASTER_PASSWORD_HASH = bcrypt.hashSync(MASTER_PASSWORD, 10);

app.use(express.static(path.join(__dirname, 'public')));

// --- ADATBÁZIS MODELLEK ---
const KeySchema = new mongoose.Schema({
  name: { type: String, required: true },
  secret: { type: String, required: true },
  createdAt: { type: Date, default: Date.now }
});

const ShareSchema = new mongoose.Schema({
  keyId: { type: mongoose.Schema.Types.ObjectId, ref: 'Key', required: true },
  label: { type: String, required: true },
  passwordHash: { type: String, required: true },
  shareToken: { type: String, required: true, unique: true },
  createdAt: { type: Date, default: Date.now, expires: 60 } // 60 másodperc után az adatbázis automatikusan törli
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

app.post('/api/login', async (req, res) => {
  const { password } = req.body;
  if (bcrypt.compareSync(password, MASTER_PASSWORD_HASH)) {
    const token = jwt.sign({ role: 'owner' }, JWT_SECRET, { expiresIn: '7d' });
    return res.json({ token });
  }
  res.status(401).json({ error: 'Hibás mesterjelszó!' });
});

app.get('/api/keys', isOwner, async (req, res) => {
  const keys = await Key.find();
  const result = keys.map(k => ({
    id: k._id,
    name: k.name,
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

app.post('/api/shares', isOwner, async (req, res) => {
  const { keyId, label } = req.body;
  const password = crypto.randomBytes(4).toString('hex');
  const shareToken = crypto.randomBytes(16).toString('hex');
  const passwordHash = bcrypt.hashSync(password, 10);
  const share = new Share({ keyId, label, passwordHash, shareToken });
  await share.save();
  res.json({ shareToken, password, label });
});

app.get('/api/shares', isOwner, async (req, res) => {
  const shares = await Share.find().populate('keyId', 'name');
  res.json(shares);
});

app.delete('/api/shares/:id', isOwner, async (req, res) => {
  await Share.findByIdAndDelete(req.params.id);
  res.json({ success: true });
});

app.post('/api/public/code', async (req, res) => {
  const { token, password } = req.body;
  const share = await Share.findOne({ shareToken: token }).populate('keyId');
  
  if (!share || !share.keyId) return res.status(404).json({ error: 'Nincs ilyen megosztás vagy lejárt' });

  // Manuális ellenőrzés a biztos 1 perces lejárathoz
  const now = new Date();
  const diffInSeconds = (now - share.createdAt) / 1000;
  if (diffInSeconds > 60) {
    await Share.findByIdAndDelete(share._id);
    return res.status(410).json({ error: 'A megosztási link 1 perc után lejárt' });
  }

  if (!bcrypt.compareSync(password, share.passwordHash)) return res.status(401).json({ error: 'Hibás jelszó' });

  res.json({
    name: share.keyId.name,
    code: otplib.authenticator.generate(share.keyId.secret),
    remaining: otplib.authenticator.timeRemaining()
  });
});

app.get('*', (req, res) => {
  res.sendFile(path.join(__dirname, 'public', 'index.html'));
});

mongoose.connect(MONGO_URI).then(() => {
  app.listen(PORT, () => console.log(`Szerver fut a ${PORT} porton.`));
});
