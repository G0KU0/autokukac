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
const JWT_SECRET = process.env.JWT_SECRET || 'top-secret-key';
const MASTER_PASSWORD = process.env.MASTER_PASSWORD || 'admin123';

app.use(express.static(path.join(__dirname, 'public')));

// ADATBÁZIS MODELLEK (Nincs 'expires' mező, tehát nem törlődik!)
const Key = mongoose.model('Key', new mongoose.Schema({
    name: String, secret: String, createdAt: { type: Date, default: Date.now }
}));

const Share = mongoose.model('Share', new mongoose.Schema({
    keyId: { type: mongoose.Schema.Types.ObjectId, ref: 'Key' },
    email: { type: String, lowercase: true, trim: true },
    password: String,
    shareToken: String,
    allowedIp: { type: String, default: null },
    sessionStartedAt: { type: Date, default: null }, // Az 1 perces ablak kezdete
    createdAt: { type: Date, default: Date.now }
}));

const auth = (req, res, next) => {
    try {
        const decoded = jwt.verify(req.headers.authorization, JWT_SECRET);
        next();
    } catch (e) { res.status(401).json({ error: 'Bejelentkezés szükséges' }); }
};

// --- ADMIN API ---
app.post('/api/login', (req, res) => {
    if (req.body.password === MASTER_PASSWORD) {
        return res.json({ token: jwt.sign({ role: 'admin' }, JWT_SECRET, { expiresIn: '7d' }) });
    }
    res.status(401).json({ error: 'Hibás admin jelszó!' });
});

app.get('/api/keys', auth, async (req, res) => {
    const keys = await Key.find();
    res.json(keys.map(k => ({
        id: k._id, name: k.name,
        code: otplib.authenticator.generate(k.secret),
        remaining: otplib.authenticator.timeRemaining()
    })));
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
        keyId: req.body.keyId,
        email: req.body.email,
        password: crypto.randomBytes(3).toString('hex'),
        shareToken: crypto.randomBytes(12).toString('hex')
    });
    await share.save(); res.json(share);
});

app.patch('/api/shares/:id', auth, async (req, res) => {
    await Share.findByIdAndUpdate(req.params.id, req.body);
    res.json({ success: true });
});

app.delete('/api/shares/:id', auth, async (req, res) => {
    await Share.findByIdAndDelete(req.params.id);
    res.json({ success: true });
});

// --- VENDÉG API (A LÉNYEG) ---
app.post('/api/public/get-code', async (req, res) => {
    const { token, email, password, startTimer } = req.body;
    const clientIp = req.headers['x-forwarded-for']?.split(',')[0] || req.ip;

    const share = await Share.findOne({ shareToken: token }).populate('keyId');
    
    // 1. Ellenőrzés: Létezik, jó az email és a jelszó?
    if (!share || share.email !== email.trim().toLowerCase() || share.password !== password) {
        return res.status(401).json({ error: 'Hibás email vagy jelszó!' });
    }

    // 2. IP Lock
    if (!share.allowedIp) {
        share.allowedIp = clientIp;
        await share.save();
    } else if (share.allowedIp !== clientIp) {
        return res.status(403).json({ error: 'Ez a link le van védve egy másik eszközhöz!' });
    }

    const now = new Date();
    const ONE_MINUTE = 60 * 1000;
    const TWENTY_FOUR_HOURS = 24 * 60 * 60 * 1000;

    // Megnézzük, mikor volt az utolsó munkamenet
    const isSessionExpired = share.sessionStartedAt && (now - share.sessionStartedAt) < TWENTY_FOUR_HOURS;
    const isInActiveMinute = share.sessionStartedAt && (now - share.sessionStartedAt) < ONE_MINUTE;

    // Ha rákattintott az OK-ra és eltel már 24 óra (vagy ez az első alkalom)
    if (startTimer) {
        if (!share.sessionStartedAt || (now - share.sessionStartedAt) >= TWENTY_FOUR_HOURS) {
            share.sessionStartedAt = now;
            await share.save();
        }
    }

    // Ha még 24 órán belül van, de már letelt az 1 perc
    if (isSessionExpired && !isInActiveMinute) {
        const nextTime = new Date(share.sessionStartedAt.getTime() + TWENTY_FOUR_HOURS);
        return res.status(403).json({ 
            error: `A napi 1 perces kereted lejárt. Újra elérhető: ${nextTime.toLocaleString('hu-HU')}` 
        });
    }

    // Ha nincs még aktív munkamenet és nem is most indította el (csak bejelentkezett)
    if (!isInActiveMinute && !startTimer) {
        return res.json({ ready: true });
    }

    // KÓD KÜLDÉSE (Csak ha az 1 perces ablakban vagyunk)
    res.json({
        name: share.keyId?.name || "Ismeretlen",
        code: otplib.authenticator.generate(share.keyId.secret),
        remaining: otplib.authenticator.timeRemaining(),
        expiresIn: Math.max(0, Math.floor((ONE_MINUTE - (now - share.sessionStartedAt)) / 1000))
    });
});

app.get('*', (req, res) => res.sendFile(path.join(__dirname, 'public', 'index.html')));

mongoose.connect(MONGO_URI).then(() => app.listen(PORT));
