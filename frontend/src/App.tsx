import { useState, useEffect } from 'react';
import './App.css';

const API = 'http://127.0.0.1:8000';

export default function App() {
  const [tab, setTab] = useState('checker');
  return (
    <div className="container">
      <h1>🛡️ Phishing Detector</h1>
      <div className="tabs">
        <button className={tab === 'checker' ? 'active' : ''} onClick={() => setTab('checker')}>Checker</button>
        <button className={tab === 'dashboard' ? 'active' : ''} onClick={() => setTab('dashboard')}>Dashboard</button>
      </div>
      {tab === 'checker' ? <Checker /> : <Dashboard />}
    </div>
  );
}

function Checker() {
  const [url, setUrl] = useState('');
  const [result, setResult] = useState(null);
  const [loading, setLoading] = useState(false);

  const check = async () => {
    if (!url) return;
    setLoading(true);
    const res = await fetch(`${API}/predict`, {
      method: 'POST', headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({ url }),
    });
    setResult(await res.json());
    setLoading(false);
  };

  const report = async () => {
    const domain = new URL(url.includes('://') ? url : 'http://' + url).hostname;
    await fetch(`${API}/report`, {
      method: 'POST', headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({ domain }),
    });
    alert('Reported: ' + domain);
  };

  return (
    <div className="card">
      <div className="input-row">
        <input value={url} onChange={(e) => setUrl(e.target.value)}
               placeholder="Enter a URL, e.g. http://secure-login.paypal-verify.xyz"
               onKeyDown={(e) => e.key === 'Enter' && check()} />
        <button onClick={check} disabled={loading}>{loading ? 'Checking...' : 'Check'}</button>
      </div>

      {result && (
        <div className={`result ${result.verdict}`}>
          <h3>{result.verdict === 'phishing' ? '⚠ Phishing detected' : '✓ Legitimate'}</h3>
          <p>Confidence: {(result.confidence * 100).toFixed(1)}%</p>
          <p>Resolved by: {result.stage_used === 'stage1_fast' ? 'Stage 1 (fast, ~6ms)' : 'Stage 2 (deep, ~34ms)'}</p>
          {result.verdict === 'phishing' && <button onClick={report}>Report this site</button>}
        </div>
      )}
    </div>
  );
}

function Dashboard() {
  const [stats, setStats] = useState(null);

  useEffect(() => {
    fetch(`${API}/stats`).then((r) => r.json()).then(setStats);
  }, []);

  if (!stats) return <p>Loading...</p>;

  return (
    <div>
      <div className="stat-row">
        <div className="stat-box"><div className="num">{stats.total_scans}</div><div className="label">Total scans</div></div>
        <div className="stat-box"><div className="num">{stats.phishing_blocked}</div><div className="label">Phishing blocked</div></div>
      </div>

      <div className="list-card">
        <h3>Recent scans</h3>
        {stats.recent.map((r, i) => (
          <div className="list-item" key={i}>
            <span>{r.url}</span>
            <span className={`badge ${r.verdict}`}>{r.verdict}</span>
          </div>
        ))}
      </div>

      <div className="list-card">
        <h3>Top reported domains</h3>
        {stats.top_reported.length === 0 && <p style={{ color: '#a1a1aa', fontSize: 14 }}>No reports yet</p>}
        {stats.top_reported.map((r, i) => (
          <div className="list-item" key={i}>
            <span>{r.domain}</span><span>{r.count} reports</span>
          </div>
        ))}
      </div>
    </div>
  );
}