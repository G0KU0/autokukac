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

const PORT = process.env.PORT || 5000;
const MONGO_URI = process.env.MONGO_URI || 'mongodb://127.0.0.1:27017/authenticator_db';
const JWT_SECRET = process.env.JWT_SECRET || 'szaby-titkos-kulcs-2024';
const MASTER_PASSWORD = process.env.MASTER_PASSWORD || 'admin123';

app.use(express.static(path.join(__dirname, 'public')));

// --- ADATBÁZIS MODELLEK ---
const Key = mongoose.model('Key', new mongoose.Schema({
    name: String, secret: String, createdAt: { type: Date, default: Date.now }
}));

const Share = mongoose.model('Share', new mongoose.Schema({
    keyId: { type: mongoose.Schema.Types.ObjectId, ref: 'Key' },
    email: { type: String, lowercase: true, trim: true },
    password: String,
    shareToken: String,
    allowedIp: { type: String, default: null },
    sessionStartedAt: { type: Date, default: null },
    createdAt: { type: Date, default: Date.now }
}));

const auth = (req, res, next) => {
    try {
        const decoded = jwt.verify(req.headers.authorization, JWT_SECRET);
        next();
    } catch (e) { res.status(401).json({ error: 'Admin auth szükséges' }); }
};

// --- ADMIN API ---
app.post('/api/login', (req, res) => {
    if (req.body.password === MASTER_PASSWORD) {
        return res.json({ token: jwt.sign({ role: 'admin' }, JWT_SECRET, { expiresIn: '7d' }) });
    }
    res.status(401).json({ error: 'Hibás jelszó!' });
});

app.get('/api/keys', auth, async (req, res) => {
    try {
        const keys = await Key.find();
        res.json(keys.map(k => ({
            id: k._id, name: k.name,
            code: otplib.authenticator.generate(k.secret),
            remaining: otplib.authenticator.timeRemaining()
        })));
    } catch(e) { res.status(500).json({error: "Hiba"}); }
});

app.post('/api/keys', auth, async (req, res) => {
    const key = new Key({ name: req.body.name, secret: req.body.secret.replace(/\s/g, '').toUpperCase() });
    await key.save(); res.json(key);
});

app.delete('/api/keys/:id', auth, async (req, res) => {
    await Key.findByIdAndDelete(req.params.id);
    await Share.deleteMany({ keyId: req.params.id });
    res.json({ success: true });
});

app.get('/api/shares', auth, async (req, res) => {
    const shares = await Share.find().populate('keyId');
    res.json(shares);
});

app.post('/api/shares', auth, async (req, res) => {
    const share = new Share({
        keyId: req.body.keyId, email: req.body.email,
        password: crypto.randomBytes(3).toString('hex'),
        shareToken: crypto.randomBytes(12).toString('hex')
    });
    await share.save(); res.json(share);
});

// TELJES RESET: Időzítő és IP törlése
app.post('/api/shares/:id/reset', auth, async (req, res) => {
    await Share.findByIdAndUpdate(req.params.id, { sessionStartedAt: null, allowedIp: null });
    res.json({ success: true });
});

app.patch('/api/shares/:id', auth, async (req, res) => {
    await Share.findByIdAndUpdate(req.params.id, req.body);
    res.json({ success: true });
});

app.delete('/api/shares/:id', auth, async (req, res) => {
    await Share.findByIdAndDelete(req.params.id);
    res.json({ success: true });
});

// --- VENDÉG API ---
app.post('/api/public/get-code', async (req, res) => {
    const { token, email, password, startTimer } = req.body;
    const clientIp = req.headers['x-forwarded-for']?.split(',')[0] || req.ip;

    const share = await Share.findOne({ shareToken: token }).populate('keyId');
    if (!share || share.email !== email.trim().toLowerCase() || share.password !== password) {
        return res.status(401).json({ error: 'Hibás adatok!' });
    }

    if (!share.allowedIp) { share.allowedIp = clientIp; await share.save(); }
    else if (share.allowedIp !== clientIp) return res.status(403).json({ error: 'Ez a kulcs más eszközhöz van kötve!' });

    const now = new Date();
    const ONE_MINUTE = 60000;
    const DAY = 86400000;

    const isCooldown = share.sessionStartedAt && (now - share.sessionStartedAt) < DAY;
    const isActive = share.sessionStartedAt && (now - share.sessionStartedAt) < ONE_MINUTE;

    if (startTimer) {
        if (!share.sessionStartedAt || (now - share.sessionStartedAt) >= DAY) {
            share.sessionStartedAt = now;
            await share.save();
        }
    }

    if (isCooldown && !isActive) {
        const nextDate = new Date(share.sessionStartedAt.getTime() + DAY);
        return res.status(403).json({ error: `Keret lejárt. Újra: ${nextDate.toLocaleString('hu-HU')}` });
    }

    if (!isActive && !startTimer) return res.json({ ready: true });

    res.json({
        name: share.keyId?.name || "Ismeretlen",
        code: otplib.authenticator.generate(share.keyId.secret),
        remaining: otplib.authenticator.timeRemaining(),
        expiresIn: Math.max(0, Math.floor((ONE_MINUTE - (now - share.sessionStartedAt)) / 1000))
    });
});

app.get('*', (req, res) => res.sendFile(path.join(__dirname, 'public', 'index.html')));

mongoose.connect(MONGO_URI).then(() => app.listen(PORT));
