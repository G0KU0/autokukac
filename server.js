require('dotenv').config();
const express = require('express');
const mongoose = require('mongoose');
const jwt = require('jsonwebtoken');
const crypto = require('crypto');
const otplib = require('otplib');
const cors = require('cors');
const path = require('path');

const app = express();
app.set('trust proxy', true); 
app.use(express.json());
app.use(cors());

// Konfiguráció
const PORT = process.env.PORT || 5000;
const MONGO_URI = process.env.MONGO_URI || 'mongodb://127.0.0.1:27017/authenticator_db';
const JWT_SECRET = process.env.JWT_SECRET || 'titkos-kulcs-123';
const MASTER_PASSWORD = process.env.MASTER_PASSWORD || 'admin123';

app.use(express.static(path.join(__dirname, 'public')));

const KeySchema = new mongoose.Schema({
  name: { type: String, required: true },
  secret: { type: String, required: true },
  createdAt: { type: Date, default: Date.now }
});

const ShareSchema = new mongoose.Schema({
  keyId: { type: mongoose.Schema.Types.ObjectId, ref: 'Key', required: true },
  label: { type: String, required: true },
  password: { type: String, required: true },
  shareToken: { type: String, required: true, unique: true },
  allowedIp: { type: String, default: null },
  sessionStartedAt: { type: Date, default: null },
  createdAt: { type: Date, default: Date.now }
});

const Key = mongoose.model('Key', KeySchema);
const Share = mongoose.model('Share', ShareSchema);

const isOwner = (req, res, next) => {
  const token = req.headers['authorization'];
  if (!token) return res.status(401).json({ error: 'Nincs bejelentkezve' });
  try {
    const decoded = jwt.verify(token, JWT_SECRET);
    req.user = decoded;
    next();
  } catch (e) { res.status(401).json({ error: 'Érvénytelen munkamenet' }); }
};

// API Útvonalak
app.post('/api/login', (req, res) => {
  const { password } = req.body;
  if (password === MASTER_PASSWORD) {
    const token = jwt.sign({ role: 'owner' }, JWT_SECRET, { expiresIn: '7d' });
    return res.json({ token });
  }
  res.status(401).json({ error: 'Hibás mesterjelszó!' });
});

app.get('/api/keys', isOwner, async (req, res) => {
  try {
    const keys = await Key.find();
    res.json(keys.map(k => ({
      id: k._id, name: k.name,
      code: otplib.authenticator.generate(k.secret),
      remaining: otplib.authenticator.timeRemaining()
    })));
  } catch (e) { res.status(500).json({ error: "DB hiba" }); }
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

app.get('/api/shares', isOwner, async (req, res) => {
  const shares = await Share.find().populate('keyId', 'name');
  res.json(shares);
});

app.post('/api/shares', isOwner, async (req, res) => {
  const { keyId, label } = req.body;
  const password = crypto.randomBytes(4).toString('hex');
  const shareToken = crypto.randomBytes(16).toString('hex');
  const share = new Share({ keyId, label, password, shareToken });
  await share.save();
  res.json(share);
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

app.post('/api/public/code', async (req, res) => {
  const { token, label, password } = req.body;
  const clientIp = req.headers['x-forwarded-for']?.split(',')[0] || req.ip;

  const share = await Share.findOne({ shareToken: token }).populate('keyId');
  if (!share) return res.status(404).json({ error: 'Érvénytelen link' });
  if (share.label !== label || share.password !== password) return res.status(401).json({ error: 'Hibás név vagy jelszó' });

  if (!share.allowedIp) {
    share.allowedIp = clientIp;
    await share.save();
  } else if (share.allowedIp !== clientIp) {
    return res.status(403).json({ error: 'Ez a hozzáférés más eszközhöz van kötve!' });
  }

  const now = new Date();
  if (!share.sessionStartedAt || (now - share.sessionStartedAt) >= 86400000) {
    share.sessionStartedAt = now;
    await share.save();
  }

  const elapsed = now - share.sessionStartedAt;
  if (elapsed > 60000) return res.status(403).json({ error: 'A napi 1 perces kereted elfogyott.' });

  res.json({
    name: share.keyId.name,
    code: otplib.authenticator.generate(share.keyId.secret),
    remaining: otplib.authenticator.timeRemaining(),
    sessionExpiresIn: Math.max(0, Math.floor((60000 - elapsed) / 1000))
  });
});

app.get('*', (req, res) => {
  res.sendFile(path.join(__dirname, 'public', 'index.html'));
});

mongoose.connect(MONGO_URI).then(() => {
  app.listen(PORT, () => console.log(`Szerver fut a ${PORT} porton.`));
});
