async function checkCurrentTab() {
  const loadingEl = document.getElementById('loading');
  const resultDiv = document.getElementById('result');
  const reportBtn = document.getElementById('reportBtn');
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

    // verdict + confidence (built with textContent, so nothing from the server is run as HTML)
    resultDiv.textContent = '';
    const title = document.createElement('b');
    title.textContent = data.verdict.toUpperCase();
    resultDiv.appendChild(title);
    resultDiv.appendChild(document.createElement('br'));
    resultDiv.appendChild(
      document.createTextNode(`Confidence: ${(data.confidence * 100).toFixed(1)}%`)
    );

    // explanation: why the model decided this (top reasons from the backend)
    if (Array.isArray(data.reasons) && data.reasons.length > 0) {
      const whyTitle = document.createElement('div');
      whyTitle.className = 'why-title';
      whyTitle.textContent = 'Why:';
      const list = document.createElement('ul');
      data.reasons.forEach((reason) => {
        const li = document.createElement('li');
        li.textContent = reason;
        list.appendChild(li);
      });
      resultDiv.appendChild(whyTitle);
      resultDiv.appendChild(list);
    }

    if (data.verdict === 'phishing') {
      reportBtn.style.display = 'inline-block';
    }

    reportBtn.addEventListener('click', async () => {
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