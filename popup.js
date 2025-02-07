document.addEventListener('DOMContentLoaded', async () => {
  const tabs = await chrome.tabs.query({ active: true, currentWindow: true });
  const url = tabs[0].url;
  
  const statusElement = document.getElementById('status');
  const resultElement = document.getElementById('result');
  const currentUrlElement = document.getElementById('currentUrl');

  // Display current URL
  currentUrlElement.textContent = url;

  try {
    const response = await chrome.runtime.sendMessage({ 
      action: 'checkUrl', 
      url: url 
    });

    if (!response) {
      throw new Error('No response from analysis');
    }

    // Remove loader and update status
    statusElement.innerHTML = 'Analysis complete';
    
    // Update result with fallback message
    resultElement.textContent = response.message || 'Analysis completed';
    resultElement.className = `result ${response.safe ? 'safe' : 'unsafe'}`;

    // Update analysis sections with null checks
    document.getElementById('safeBrowsing').innerHTML = `
      <strong>Google Safe Browsing Check</strong>
      <div class="analysis-content">
        ${response.safeBrowsingDetails || 'Analysis not available'}
      </div>
    `;

    document.getElementById('geminiAnalysis').innerHTML = `
      <strong>AI-Powered Analysis</strong>
      <div class="analysis-content">
        ${response.geminiDetails || 'Analysis not available'}
      </div>
    `;

    const urlDetails = response.urlDetails || {};
    const threatLevelClass = (urlDetails.threatLevel || 'unknown').toLowerCase();

    document.getElementById('urlAnalysis').innerHTML = `
      <strong>Technical Analysis</strong>
      <table class="details-table">
        <tr>
          <td>Domain Age:</td>
          <td>${urlDetails.domainAge || 'Unknown'}</td>
        </tr>
        <tr>
          <td>SSL Certificate:</td>
          <td>${urlDetails.ssl || 'Unknown'}</td>
        </tr>
        <tr>
          <td>Risk Score:</td>
          <td><span class="score ${getRiskClass(urlDetails.riskScore || 0)}">
            ${urlDetails.riskScore || 0}%
          </span></td>
        </tr>
        <tr>
          <td>Threat Level:</td>
          <td><span class="threat-level ${threatLevelClass}">
            ${urlDetails.threatLevel || 'Unknown'}
          </span></td>
        </tr>
        ${urlDetails.flags ? `
        <tr>
          <td>Risk Factors:</td>
          <td class="risk-factors">
            ${(urlDetails.flags || []).map(flag => 
              `<div class="risk-factor">${flag}</div>`
            ).join('')}
          </td>
        </tr>
        ` : ''}
      </table>
    `;

  } catch (error) {
    console.error('Analysis error:', error);
    statusElement.innerHTML = '❌ Error analyzing URL';
    resultElement.textContent = error?.message || 'Failed to analyze URL';
    resultElement.className = 'result unsafe';
    
    // Show error in analysis sections
    ['safeBrowsing', 'geminiAnalysis', 'urlAnalysis'].forEach(id => {
      document.getElementById(id).innerHTML = `
        <strong>${id === 'safeBrowsing' ? 'Google Safe Browsing Check' : 
                 id === 'geminiAnalysis' ? 'AI-Powered Analysis' : 
                 'Technical Analysis'}</strong>
        <div class="analysis-content">Analysis failed</div>
      `;
    });
  }
});

function getRiskClass(score) {
  if (score >= 70) return 'high-risk';
  if (score >= 40) return 'medium-risk';
  return 'low-risk';
}

function formatTechnicalDetails(details) {
  if (!details || typeof details !== 'object') return 'Not available';
  return Object.entries(details)
    .map(([key, value]) => `${key}: ${value}`)
    .join('<br>');
}

function formatDate(dateStr) {
  if (!dateStr || dateStr === 'Unknown') return 'Unknown';
  try {
    const date = new Date(dateStr);
    return date.toISOString() !== 'Invalid Date' 
      ? date.toLocaleDateString('en-US', { 
          year: 'numeric', 
          month: 'short', 
          day: 'numeric' 
        })
      : 'Unknown';
  } catch {
    return 'Unknown';
  }
}
