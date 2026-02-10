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
const JWT_SECRET = process.env.JWT_SECRET || 'titkos-kulcs-xyz';
const MASTER_PASSWORD = process.env.MASTER_PASSWORD || 'admin123';

app.use(express.static(path.join(__dirname, 'public')));

// ADATBÁZIS
const Key = mongoose.model('Key', new mongoose.Schema({
    name: String, secret: String, createdAt: { type: Date, default: Date.now }
}));

const Share = mongoose.model('Share', new mongoose.Schema({
    keyId: { type: mongoose.Schema.Types.ObjectId, ref: 'Key' },
    label: String, password: String, shareToken: String,
    allowedIp: { type: String, default: null },
    sessionStartedAt: { type: Date, default: null },
    createdAt: { type: Date, default: Date.now }
}));

// AUTH MIDDLEWARE
const auth = (req, res, next) => {
    try {
        const decoded = jwt.verify(req.headers.authorization, JWT_SECRET);
        req.user = decoded;
        next();
    } catch (e) { res.status(401).json({ error: 'Bejelentkezés szükséges' }); }
};

// API
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
        keyId: req.body.keyId, label: req.body.label,
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

app.post('/api/public/code', async (req, res) => {
    const { token, label, password } = req.body;
    const clientIp = req.headers['x-forwarded-for']?.split(',')[0] || req.ip;

    const share = await Share.findOne({ shareToken: token }).populate('keyId');
    if (!share || share.label !== label || share.password !== password) {
        return res.status(401).json({ error: 'Hibás adatok!' });
    }

    if (!share.allowedIp) { share.allowedIp = clientIp; await share.save(); }
    else if (share.allowedIp !== clientIp) return res.status(403).json({ error: 'IP tiltás: Ez a kulcs egy másik eszközhöz van kötve!' });

    const now = new Date();
    if (!share.sessionStartedAt || (now - share.sessionStartedAt) > 86400000) {
        share.sessionStartedAt = now; await share.save();
    }
    const elapsed = now - share.sessionStartedAt;
    if (elapsed > 60000) return res.status(403).json({ error: 'Mára lejárt az 1 perces kereted!' });

    res.json({
        name: share.keyId?.name || "Ismeretlen",
        code: otplib.authenticator.generate(share.keyId.secret),
        remaining: otplib.authenticator.timeRemaining(),
        expiresIn: Math.max(0, Math.floor((60000 - elapsed) / 1000))
    });
});

app.get('*', (req, res) => res.sendFile(path.join(__dirname, 'public', 'index.html')));

mongoose.connect(MONGO_URI).then(() => {
    console.log("DB Connected");
    app.listen(PORT, () => console.log("Server running"));
});
