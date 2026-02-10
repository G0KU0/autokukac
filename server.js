/**
 * SZERVER OLDAL (Backend) - Node.js & Express
 * Ez a fájl felel az adatbázis kapcsolatért és az API végpontokért.
 */
require('dotenv').config();
const express = require('express');
const mongoose = require('mongoose');
const bcrypt = require('bcryptjs');
const jwt = require('jsonwebtoken');
const crypto = require('crypto');
const otplib = require('otplib');
const cors = require('cors');

const app = express();

// Middleware-ek beállítása
app.use(express.json());
app.use(cors());

// --- KONFIGURÁCIÓ (Környezeti változókból) ---
const PORT = process.env.PORT || 5000;
const MONGO_URI = process.env.MONGO_URI || 'mongodb://127.0.0.1:27017/authenticator_db';
const JWT_SECRET = process.env.JWT_SECRET || 'titkos-kulcs-a-tokenekhez';
const MASTER_PASSWORD = process.env.MASTER_PASSWORD || 'admin123';

// A mesterjelszó hash-elt változata (a biztonság kedvéért)
const MASTER_PASSWORD_HASH = bcrypt.hashSync(MASTER_PASSWORD, 10);

// --- ADATBÁZIS MODELLEK (MongoDB) ---

// Egy adott autentikátor kulcs sémája
const KeySchema = new mongoose.Schema({
  name: { type: String, required: true },
  secret: { type: String, required: true }, // Pl. JBSWY3DPEHPK3PXP
  createdAt: { type: Date, default: Date.now }
});

// Egy megosztási meghívó sémája
const ShareSchema = new mongoose.Schema({
  keyId: { type: mongoose.Schema.Types.ObjectId, ref: 'Key', required: true },
  label: { type: String, required: true }, // Kinek szól a meghívó
  passwordHash: { type: String, required: true }, // A megosztáshoz tartozó egyedi jelszó
  shareToken: { type: String, required: true, unique: true }, // Az URL-ben szereplő azonosító
  createdAt: { type: Date, default: Date.now }
});

const Key = mongoose.model('Key', KeySchema);
const Share = mongoose.model('Share', ShareSchema);

// --- HITELLESÍTÉS (Tulajdonos ellenőrzése) ---
const isOwner = (req, res, next) => {
  const token = req.headers['authorization'];
  if (!token) return res.status(401).json({ error: 'Nincs bejelentkezve' });
  
  try {
    const decoded = jwt.verify(token, JWT_SECRET);
    req.user = decoded;
    next();
  } catch (e) {
    res.status(401).json({ error: 'Érvénytelen vagy lejárt munkamenet' });
  }
};

// --- API ÚTVONALAK ---

/** * ADMIN BEJELENTKEZÉS 
 * Ellenőrzi a mesterjelszót és visszaküld egy JWT tokent.
 */
app.post('/api/login', async (req, res) => {
  const { password } = req.body;
  if (bcrypt.compareSync(password, MASTER_PASSWORD_HASH)) {
    const token = jwt.sign({ role: 'owner' }, JWT_SECRET, { expiresIn: '7d' });
    return res.json({ token });
  }
  res.status(401).json({ error: 'Hibás mesterjelszó!' });
});

/** * KULCSOK LISTÁZÁSA (Admin)
 * Lekéri az összes kulcsot és legenerálja hozzájuk az aktuális 6 jegyű kódot.
 */
app.get('/api/keys', isOwner, async (req, res) => {
  try {
    const keys = await Key.find();
    const result = keys.map(k => ({
      id: k._id,
      name: k.name,
      code: otplib.authenticator.generate(k.secret),
      remaining: otplib.authenticator.timeRemaining()
    }));
    res.json(result);
  } catch (err) {
    res.status(500).json({ error: 'Szerver hiba a lekéréskor' });
  }
});

/** * ÚJ KULCS HOZZÁADÁSA (Admin)
 */
app.post('/api/keys', isOwner, async (req, res) => {
  const { name, secret } = req.body;
  if (!name || !secret) return res.status(400).json({ error: 'Név és titkos kulcs megadása kötelező' });
  
  try {
    const newKey = new Key({ 
      name, 
      secret: secret.replace(/\s/g, '').toUpperCase() 
    });
    await newKey.save();
    res.json(newKey);
  } catch (err) {
    res.status(500).json({ error: 'Nem sikerült elmenteni a kulcsot' });
  }
});

/** * KULCS TÖRLÉSE (Admin)
 */
app.delete('/api/keys/:id', isOwner, async (req, res) => {
  try {
    await Key.findByIdAndDelete(req.params.id);
    // Ha törlünk egy kulcsot, az összes hozzá tartozó megosztást is töröljük
    await Share.deleteMany({ keyId: req.params.id });
    res.json({ success: true });
  } catch (err) {
    res.status(500).json({ error: 'Hiba a törlés során' });
  }
});

/** * MEGOSZTÁS LÉTREHOZÁSA (Admin)
 */
app.post('/api/shares', isOwner, async (req, res) => {
  const { keyId, label } = req.body;
  if (!keyId || !label) return res.status(400).json({ error: 'Hiányzó adatok' });

  try {
    const password = crypto.randomBytes(4).toString('hex'); // Generált jelszó (pl. 'a1b2c3d4')
    const shareToken = crypto.randomBytes(16).toString('hex'); // Egyedi URL azonosító
    const passwordHash = bcrypt.hashSync(password, 10);
    
    const share = new Share({ keyId, label, passwordHash, shareToken });
    await share.save();
    
    // A jelszót csak most küldjük el egyszer, a hash-t tároljuk
    res.json({ shareToken, password, label });
  } catch (err) {
    res.status(500).json({ error: 'Megosztás sikertelen' });
  }
});

/** * AKTÍV MEGOSZTÁSOK LISTÁZÁSA (Admin)
 */
app.get('/api/shares', isOwner, async (req, res) => {
  const shares = await Share.find().populate('keyId', 'name');
  res.json(shares);
});

/** * MEGOSZTÁS TÖRLÉSE / VISSZAVONÁSA (Admin)
 */
app.delete('/api/shares/:id', isOwner, async (req, res) => {
  await Share.findByIdAndDelete(req.params.id);
  res.json({ success: true });
});

/** * PUBLIKUS KÓD LEKÉRÉSE (Vendég nézet)
 * Itt nem kell JWT, csak a shareToken és a hozzá tartozó jelszó.
 */
app.post('/api/public/code', async (req, res) => {
  const { token, password } = req.body;
  
  try {
    const share = await Share.findOne({ shareToken: token }).populate('keyId');
    
    if (!share || !share.keyId) {
      return res.status(404).json({ error: 'Ez a megosztás nem létezik vagy visszavonták.' });
    }

    if (!bcrypt.compareSync(password, share.passwordHash)) {
      return res.status(401).json({ error: 'Hibás megosztási jelszó!' });
    }

    // Csak a nevet és az aktuális kódot küldjük el, a titkos kulcsot (secret) nem!
    res.json({
      name: share.keyId.name,
      code: otplib.authenticator.generate(share.keyId.secret),
      remaining: otplib.authenticator.timeRemaining()
    });
  } catch (err) {
    res.status(500).json({ error: 'Hiba a kód lekérésekor' });
  }
});

// --- SZERVER INDÍTÁSA ÉS ADATBÁZIS KAPCSOLAT ---
mongoose.connect(MONGO_URI)
  .then(() => {
    console.log('✅ MongoDB kapcsolat sikeresen felépítve!');
    app.listen(PORT, () => {
      console.log(`🚀 Authenticator szerver elindult a ${PORT} porton.`);
      console.log(`🔑 Alapértelmezett mesterjelszó: ${MASTER_PASSWORD}`);
    });
  })
  .catch(err => {
    console.error('❌ MongoDB kapcsolódási hiba:', err.message);
    process.exit(1);
  });
