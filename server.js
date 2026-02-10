require('dotenv').config();
const express = require('express');
const mongoose = require('mongoose');
const jwt = require('jsonwebtoken');
const crypto = require('crypto');
const otplib = require('otplib');
const cors = require('cors');
const path = require('path');

const app = express();

// FONTOS Render-en a valódi IP címekhez
app.set('trust proxy', true);
app.use(express.json());
app.use(cors());

// --- KONFIGURÁCIÓ ---
const PORT = process.env.PORT || 5000;
const MONGO_URI = process.env.MONGO_URI || 'mongodb://127.0.0.1:27017/authenticator_db';
const JWT_SECRET = process.env.JWT_SECRET || 'super-secret-key-88';
const MASTER_PASSWORD = process.env.MASTER_PASSWORD || 'admin123';

// Statikus fájlok kiszolgálása
app.use(express.static(path.join(__dirname, 'public')));

// --- ADATBÁZIS MODELLEK ---
const Key = mongoose.model('Key', new mongoose.Schema({
    name: String,
    secret: String,
    createdAt: { type: Date, default: Date.now }
}));

const Share = mongoose.model('Share', new mongoose.Schema({
    keyId: { type: mongoose.Schema.Types.ObjectId, ref: 'Key' },
    label: String,      // A vendég neve
    password: String,   // A vendég jelszava (olvasható az adminnak)
    shareToken: String, // Egyedi azonosító a linkhez
    allowedIp: { type: String, default: null },
    sessionStartedAt: { type: Date, default: null },
    createdAt: { type: Date, default: Date.now }
}));

// --- ADMIN AUTH MIDDLEWARE ---
const auth = (req, res, next) => {
    try {
        const token = req.headers.authorization;
        const decoded = jwt.verify(token, JWT_SECRET);
        req.user = decoded;
        next();
    } catch (e) {
        res.status(401).json({ error: 'Bejelentkezés szükséges' });
    }
};

// --- API ÚTVONALAK ---

// Admin Login
app.post('/api/login', (req, res) => {
    if (req.body.password === MASTER_PASSWORD) {
        const token = jwt.sign({ role: 'admin' }, JWT_SECRET, { expiresIn: '7d' });
        return res.json({ token });
    }
    res.status(401).json({ error: 'Hibás admin jelszó!' });
});

// Admin: Kulcsok kezelése
app.get('/api/keys', auth, async (req, res) => {
    const keys = await Key.find();
    res.json(keys.map(k => ({
        id: k._id,
        name: k.name,
        code: otplib.authenticator.generate(k.secret),
        remaining: otplib.authenticator.timeRemaining()
    })));
});

app.post('/api/keys', auth, async (req, res) => {
    const key = new Key({ 
        name: req.body.name, 
        secret: req.body.secret.replace(/\s/g, '').toUpperCase() 
    });
    await key.save();
    res.json(key);
});

app.delete('/api/keys/:id', auth, async (req, res) => {
    await Key.findByIdAndDelete(req.params.id);
    await Share.deleteMany({ keyId: req.params.id });
    res.json({ success: true });
});

// Admin: Megosztások kezelése
app.get('/api/shares', auth, async (req, res) => {
    const shares = await Share.find().populate('keyId');
    res.json(shares);
});

app.post('/api/shares', auth, async (req, res) => {
    const share = new Share({
        keyId: req.body.keyId,
        label: req.body.label,
        password: crypto.randomBytes(3).toString('hex'), // Alapértelmezett véletlen jelszó
        shareToken: crypto.randomBytes(12).toString('hex')
    });
    await share.save();
    res.json(share);
});

app.patch('/api/shares/:id', auth, async (req, res) => {
    await Share.findByIdAndUpdate(req.params.id, req.body);
    res.json({ success: true });
});

app.delete('/api/shares/:id', auth, async (req, res) => {
    await Share.findByIdAndDelete(req.params.id);
    res.json({ success: true });
});

// VENDÉG API: Kód lekérése
app.post('/api/public/code', async (req, res) => {
    const { token, label, password } = req.body;
    // Render IP detektálás
    const clientIp = req.headers['x-forwarded-for']?.split(',')[0] || req.ip;

    const share = await Share.findOne({ shareToken: token }).populate('keyId');
    if (!share) return res.status(404).json({ error: 'A link érvénytelen' });

    // 1. Név és Jelszó check
    if (share.label !== label || share.password !== password) {
        return res.status(401).json({ error: 'Hibás név vagy jelszó!' });
    }

    // 2. IP Lock
    if (!share.allowedIp) {
        share.allowedIp = clientIp;
        await share.save();
    } else if (share.allowedIp !== clientIp) {
        return res.status(403).json({ error: 'Ez a kulcs már egy másik eszközhöz van kötve!' });
    }

    // 3. Időkorlát (1 perc / 24 óra)
    const now = new Date();
    const isNewDay = !share.sessionStartedAt || (now - share.sessionStartedAt) > 86400000;
    
    if (isNewDay) {
        share.sessionStartedAt = now;
        await share.save();
    }

    const elapsed = now - share.sessionStartedAt;
    if (elapsed > 60000) {
        return res.status(403).json({ error: 'A mai 1 perces kereted elfogyott! Gyere vissza holnap.' });
    }

    res.json({
        name: share.keyId.name,
        code: otplib.authenticator.generate(share.keyId.secret),
        remaining: otplib.authenticator.timeRemaining(),
        expiresIn: Math.max(0, Math.floor((60000 - elapsed) / 1000))
    });
});

// SPA Routing: Minden ismeretlen út az index.html-re megy
app.get('*', (req, res) => {
    res.sendFile(path.join(__dirname, 'public', 'index.html'));
});

// Start
mongoose.connect(MONGO_URI).then(() => {
    app.listen(PORT, () => console.log(`>>> Szerver fut a ${PORT} porton`));
});
