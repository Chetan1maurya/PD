async function checkCurrentTab() {
  const loadingEl = document.getElementById('loading');
  const resultDiv = document.getElementById('result');
  const [tab] = await chrome.tabs.query({ active: true, currentWindow: true });

  if (!tab.url || !tab.url.startsWith('http')) {
    loadingEl.textContent = 'This page type cannot be checked (not a regular website).';
    return;
  }

  try {
    const res = await fetch('http://127.0.0.1:8000/predict', {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({ url: tab.url }),
    });

    if (!res.ok) throw new Error(`Server returned ${res.status}`);
    const data = await res.json();

    loadingEl.style.display = 'none';
    resultDiv.style.display = 'block';
    resultDiv.className = data.verdict === 'phishing' ? 'risky' : 'safe';
    resultDiv.innerHTML = `<b>${data.verdict.toUpperCase()}</b><br>Confidence: ${(data.confidence * 100).toFixed(1)}%`;

    if (data.verdict === 'phishing') {
      document.getElementById('reportBtn').style.display = 'inline-block';
    }

    document.getElementById('reportBtn').addEventListener('click', async () => {
      const domain = new URL(tab.url).hostname;
      await fetch('http://127.0.0.1:8000/report', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ domain }),
      });
      document.getElementById('status').textContent = `Reported: ${domain}`;
    });
  } catch (err) {
    loadingEl.textContent = 'Backend not reachable. Is uvicorn running on port 8000?';
    console.error(err);
  }
}

checkCurrentTab();