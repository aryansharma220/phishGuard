document.addEventListener('DOMContentLoaded', () => {
  const urlParams = new URLSearchParams(window.location.search);
  const targetUrl = urlParams.get('url');
  const analysis = JSON.parse(decodeURIComponent(urlParams.get('analysis')));
  
  document.getElementById('targetUrl').textContent = targetUrl;
  
  const riskDetails = document.getElementById('riskDetails');
  riskDetails.innerHTML = `
    <div>
      <p>Risk Score: <span class="risk-score ${getRiskClass(analysis.urlDetails.riskScore)}">
        ${analysis.urlDetails.riskScore}%
      </span></p>
      <p>Threat Level: ${analysis.urlDetails.threatLevel}</p>
      <h4>Risk Factors:</h4>
      <ul>
        ${analysis.urlDetails.flags.map(flag => `<li>${flag}</li>`).join('')}
      </ul>
    </div>
  `;

  document.getElementById('proceedBtn').addEventListener('click', () => {
    chrome.runtime.sendMessage({ 
      action: 'proceedToUrl', 
      url: targetUrl 
    });
    window.close();
  });

  document.getElementById('cancelBtn').addEventListener('click', () => {
    window.close();
  });
});

function getRiskClass(score) {
  if (score >= 70) return 'high-risk';
  if (score >= 40) return 'medium-risk';
  return 'low-risk';
}
