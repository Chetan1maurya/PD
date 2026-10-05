chrome.runtime.onMessage.addListener((msg) => {
  if (msg.type === 'SHOW_WARNING') {
    showBanner(msg.data);
    watchPasswordFields(msg.data);
  }
});

function showBanner(data) {
  const banner = document.createElement('div');
  banner.textContent = `⚠ This site looks like phishing (${(data.confidence * 100).toFixed(0)}% confidence)`;
  banner.style.cssText = `position:fixed;top:0;left:0;width:100%;background:#c0392b;
    color:white;text-align:center;padding:10px;z-index:999999;font-family:sans-serif;`;
  document.body.prepend(banner);
}

function watchPasswordFields(data) {
  document.addEventListener('focusin', (e) => {
    if (e.target.type === 'password') {
      const proceed = confirm(
        `Warning: This site is flagged as phishing (${(data.confidence * 100).toFixed(0)}% confidence). Continue entering your password?`
      );
      if (!proceed) e.target.blur();
    }
  });
}