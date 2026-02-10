import React, { useState, useEffect } from 'react';
import { 
  Shield, Lock, Plus, Trash2, Share2, 
  RefreshCw, LogOut, Copy, Users, Key, 
  ExternalLink, CheckCircle2, AlertCircle, ChevronRight, XCircle
} from 'lucide-react';

// --- KONFIGURÁCIÓ ---
const API_BASE = 'http://localhost:5000/api'; 

const App = () => {
  const [token, setToken] = useState(localStorage.getItem('owner_token'));
  const [view, setView] = useState('loading');
  const [shareToken, setShareToken] = useState(null);
  
  // Admin állapotok
  const [password, setPassword] = useState('');
  const [keys, setKeys] = useState([]);
  const [shares, setShares] = useState([]);
  const [loading, setLoading] = useState(false);
  const [isAdding, setIsAdding] = useState(false);
  const [newName, setNewName] = useState('');
  const [newSecret, setNewSecret] = useState('');
  const [isSharing, setIsSharing] = useState(null);
  const [shareLabel, setShareLabel] = useState('');

  // Vendég állapotok
  const [guestPassword, setGuestPassword] = useState('');
  const [guestData, setGuestData] = useState(null);
  const [guestError, setGuestError] = useState('');

  useEffect(() => {
    const params = new URLSearchParams(window.location.search);
    const sToken = params.get('share');
    if (sToken) {
      setShareToken(sToken);
      setView('guest');
    } else {
      setView(token ? 'admin' : 'login');
    }
  }, [token]);

  const refreshAdminData = async () => {
    if (!token || view !== 'admin') return;
    try {
      const h = { 'Authorization': token };
      const [kRes, sRes] = await Promise.all([
        fetch(`${API_BASE}/keys`, { headers: h }),
        fetch(`${API_BASE}/shares`, { headers: h })
      ]);
      if (kRes.ok) setKeys(await kRes.json());
      if (sRes.ok) setShares(await sRes.json());
    } catch (e) { console.error("Szerver hiba"); }
  };

  useEffect(() => {
    if (view === 'admin') {
      refreshAdminData();
      const interval = setInterval(refreshAdminData, 10000);
      return () => clearInterval(interval);
    }
  }, [view, token]);

  // --- FUNKCIÓK ---
  const handleLogin = async () => {
    setLoading(true);
    const res = await fetch(`${API_BASE}/login`, {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({ password })
    });
    const data = await res.json();
    if (res.ok) {
      setToken(data.token);
      localStorage.setItem('owner_token', data.token);
      setView('admin');
    } else { alert(data.error); }
    setLoading(false);
  };

  const addKey = async () => {
    await fetch(`${API_BASE}/keys`, {
      method: 'POST',
      headers: { 'Content-Type': 'application/json', 'Authorization': token },
      body: JSON.stringify({ name: newName, secret: newSecret })
    });
    setNewName(''); setNewSecret(''); setIsAdding(false);
    refreshAdminData();
  };

  const deleteKey = async (id) => {
    if (!confirm("Biztosan törlöd a kulcsot és az összes hozzá tartozó megosztást?")) return;
    await fetch(`${API_BASE}/keys/${id}`, {
      method: 'DELETE',
      headers: { 'Authorization': token }
    });
    refreshAdminData();
  };

  const createShare = async (keyId) => {
    const res = await fetch(`${API_BASE}/shares`, {
      method: 'POST',
      headers: { 'Content-Type': 'application/json', 'Authorization': token },
      body: JSON.stringify({ keyId, label: shareLabel })
    });
    const data = await res.json();
    const shareLink = `${window.location.origin}${window.location.pathname}?share=${data.shareToken}`;
    prompt("HOZZÁFÉRÉS LÉTREHOZVA!\nKüldd el ezt a linket és jelszót:", `Link: ${shareLink} | Jelszó: ${data.password}`);
    setShareLabel(''); setIsSharing(null);
    refreshAdminData();
  };

  // EZ A FUNKCIÓ VONJA BE A MEGHÍVÓT
  const revokeShare = async (id) => {
    if (!confirm("Biztosan vissza akarod vonni ezt a hozzáférést? A link azonnal meg fog szűnni.")) return;
    await fetch(`${API_BASE}/shares/${id}`, {
      method: 'DELETE',
      headers: { 'Authorization': token }
    });
    refreshAdminData();
  };

  const unlockShare = async () => {
    setLoading(true);
    const res = await fetch(`${API_BASE}/public/code`, {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({ token: shareToken, password: guestPassword })
    });
    const data = await res.json();
    if (res.ok) { setGuestData(data); setGuestError(''); }
    else { setGuestError(data.error); setGuestData(null); }
    setLoading(false);
  };

  // --- UI RÉSZEK ---
  if (view === 'loading') return <div className="min-h-screen bg-black flex items-center justify-center"><RefreshCw className="animate-spin text-blue-500" /></div>;

  if (view === 'login') return (
    <div className="min-h-screen bg-black flex items-center justify-center p-4">
      <div className="w-full max-w-sm bg-zinc-900 border border-zinc-800 p-8 rounded-[2.5rem] shadow-2xl">
        <Lock className="text-blue-500 mx-auto mb-6" size={40} />
        <h1 className="text-white text-2xl font-bold text-center mb-8">Admin Belépés</h1>
        <input type="password" placeholder="Mesterjelszó" className="w-full bg-zinc-800 border-none rounded-2xl p-4 text-white mb-4 outline-none focus:ring-2 focus:ring-blue-500" value={password} onChange={e => setPassword(e.target.value)} onKeyDown={e => e.key === 'Enter' && handleLogin()} />
        <button onClick={handleLogin} className="w-full bg-blue-600 text-white font-bold py-4 rounded-2xl">Belépés</button>
      </div>
    </div>
  );

  if (view === 'guest') return (
    <div className="min-h-screen bg-black flex items-center justify-center p-4">
      <div className="w-full max-w-md bg-zinc-900 border border-zinc-800 p-10 rounded-[2.5rem] shadow-2xl text-center">
        {!guestData ? (
          <>
            <Users className="text-blue-500 mx-auto mb-6" size={40} />
            <h1 className="text-white text-xl font-bold mb-6">Megosztott kód feloldása</h1>
            {guestError && <div className="bg-red-500/10 text-red-500 p-3 rounded-xl text-xs mb-4 border border-red-500/20">{guestError}</div>}
            <input type="password" placeholder="Megosztási jelszó" className="w-full bg-zinc-800 border-none rounded-xl p-4 text-white mb-4 outline-none" value={guestPassword} onChange={e => setGuestPassword(e.target.value)} />
            <button onClick={unlockShare} className="w-full bg-white text-black font-bold py-4 rounded-xl">Megtekintés</button>
          </>
        ) : (
          <div>
            <span className="text-blue-500 text-xs font-bold uppercase tracking-[0.2em]">{guestData.name}</span>
            <div className="text-6xl font-mono font-black text-white mt-6 mb-8 tracking-wider italic">
              {guestData.code.slice(0,3)} {guestData.code.slice(3)}
            </div>
            <div className="text-zinc-500 text-sm flex items-center justify-center gap-2">
              <RefreshCw size={14} className="animate-spin" /> Frissül: {guestData.remaining} mp
            </div>
          </div>
        )}
      </div>
    </div>
  );

  return (
    <div className="min-h-screen bg-black text-zinc-400 p-4 md:p-10">
      <div className="max-w-6xl mx-auto">
        <header className="flex justify-between items-center mb-12">
          <div className="flex items-center gap-3">
            <div className="bg-blue-600 p-2 rounded-xl text-white"><Shield size={24} /></div>
            <h1 className="text-white font-black text-xl">OWNER CONTROL</h1>
          </div>
          <button onClick={() => { setToken(null); localStorage.removeItem('owner_token'); }} className="text-zinc-600 hover:text-white transition-colors"><LogOut /></button>
        </header>

        <div className="grid lg:grid-cols-3 gap-10">
          <div className="lg:col-span-2 space-y-6">
            <div className="flex justify-between items-center">
              <h2 className="text-2xl font-bold text-white tracking-tight">Saját Kulcsok</h2>
              <button onClick={() => setIsAdding(true)} className="bg-white text-black px-5 py-2 rounded-xl font-bold text-sm">Új Kulcs</button>
            </div>

            {isAdding && (
              <div className="bg-zinc-900 p-6 rounded-3xl border border-zinc-800 space-y-4">
                <div className="grid md:grid-cols-2 gap-4">
                  <input type="text" placeholder="Név" className="bg-zinc-800 p-4 rounded-xl outline-none text-white" value={newName} onChange={e => setNewName(e.target.value)} />
                  <input type="text" placeholder="Secret Key" className="bg-zinc-800 p-4 rounded-xl outline-none text-white" value={newSecret} onChange={e => setNewSecret(e.target.value)} />
                </div>
                <div className="flex gap-2">
                  <button onClick={addKey} className="flex-1 bg-blue-600 py-3 rounded-xl font-bold text-white">Mentés</button>
                  <button onClick={() => setIsAdding(false)} className="flex-1 bg-zinc-800 py-3 rounded-xl">Mégse</button>
                </div>
              </div>
            )}

            <div className="grid gap-4">
              {keys.map(k => (
                <div key={k.id} className="bg-zinc-900/50 p-8 rounded-[2rem] border border-zinc-800 flex justify-between items-center hover:border-zinc-700 transition-all group">
                  <div>
                    <span className="text-blue-500 text-xs font-bold uppercase tracking-widest">{k.name}</span>
                    <div className="text-5xl font-mono font-black text-white mt-2 tracking-widest">{k.code.slice(0,3)} {k.code.slice(3)}</div>
                  </div>
                  <div className="flex gap-2 opacity-0 group-hover:opacity-100 transition-opacity">
                    <button onClick={() => setIsSharing(k.id)} className="p-4 bg-zinc-800 rounded-2xl hover:text-blue-500"><Share2 /></button>
                    <button onClick={() => deleteKey(k.id)} className="p-4 bg-zinc-800 rounded-2xl hover:text-red-500"><Trash2 /></button>
                  </div>
                </div>
              ))}
            </div>
          </div>

          <div className="space-y-6">
            <h3 className="text-lg font-bold text-white flex items-center gap-2"><Users size={20} className="text-blue-500" /> Meghívók</h3>
            <div className="space-y-3">
              {shares.map(s => (
                <div key={s._id} className="p-5 bg-zinc-900 rounded-3xl border border-zinc-800">
                  <div className="flex justify-between mb-2">
                    <span className="text-white font-bold">{s.label}</span>
                    <button onClick={() => revokeShare(s._id)} className="text-zinc-600 hover:text-red-500 transition-colors" title="Visszavonás">
                      <XCircle size={18} />
                    </button>
                  </div>
                  <div className="text-[10px] uppercase font-bold text-zinc-600 mb-4 tracking-tighter">Hozzáférés: {s.keyId?.name}</div>
                  <button 
                    onClick={() => {
                      const link = `${window.location.origin}${window.location.pathname}?share=${s.shareToken}`;
                      navigator.clipboard.writeText(link);
                      alert("Link a vágólapon!");
                    }}
                    className="w-full py-2 bg-zinc-800 rounded-xl text-[10px] font-bold text-blue-400 hover:bg-zinc-700 transition-colors"
                  >
                    LINK MÁSOLÁSA
                  </button>
                </div>
              ))}
              {shares.length === 0 && <p className="text-center italic text-sm text-zinc-700">Nincs aktív meghívó.</p>}
            </div>
          </div>
        </div>
      </div>

      {isSharing && (
        <div className="fixed inset-0 bg-black/90 backdrop-blur-md flex items-center justify-center p-4 z-50">
          <div className="bg-zinc-900 p-10 rounded-[3rem] max-w-sm w-full border border-zinc-800 shadow-2xl">
            <h3 className="text-xl font-bold text-white mb-6">Kinek szánod?</h3>
            <input type="text" placeholder="Pl. Rendszergazda" className="w-full bg-zinc-800 p-4 rounded-2xl mb-6 outline-none text-white border border-transparent focus:border-blue-500" value={shareLabel} onChange={e => setShareLabel(e.target.value)} />
            <div className="flex gap-3">
              <button onClick={() => createShare(isSharing)} className="flex-1 bg-blue-600 py-4 rounded-2xl font-bold text-white">Létrehozás</button>
              <button onClick={() => setIsSharing(null)} className="flex-1 bg-zinc-800 py-4 rounded-2xl">Mégse</button>
            </div>
          </div>
        </div>
      )}
    </div>
  );
};

export default App;
