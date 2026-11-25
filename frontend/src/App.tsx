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
type Result = {
  verdict: 'phishing' | 'legitimate';
  confidence: number;
  stage_used: string;
  reasons?: string[];
};

const STAGE_LABEL: Record<string, string> = {
  stage1_fast: 'Stage 1 (fast)',
  stage2_deep: 'Stage 2 (deep)',
  allowlist: 'Trusted-domain list',
};

function Checker() {
  const [url, setUrl] = useState('');
  const [result, setResult] = useState<Result | null>(null);
  const [loading, setLoading] = useState(false);

  const check = async () => {
    if (!url) return;
    setLoading(true);
    try {
      const res = await fetch(`${API}/predict`, {
        method: 'POST', headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ url }),
      });
      setResult(await res.json());
    } catch {
      alert('Backend not reachable. Is uvicorn running on port 8000?');
    }
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
          <p>Resolved by: {STAGE_LABEL[result.stage_used] ?? result.stage_used}</p>
          {(result.reasons ?? []).length > 0 && (
            <div className="reasons">
              <p>Why:</p>
              <ul>
                {(result.reasons ?? []).map((r, i) => <li key={i}>{r}</li>)}
              </ul>
            </div>
          )}
          {result.verdict === 'phishing' && <button onClick={report}>Report this site</button>}
        </div>
      )}
    </div>
  );
}