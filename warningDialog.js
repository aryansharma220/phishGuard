document.addEventListener('DOMContentLoaded', async () => {
  try {
    // Get the window ID
    const windowInfo = await chrome.windows.getCurrent();
    
    // Retrieve stored data for this warning
    const data = await chrome.storage.local.get(`warning_${windowInfo.id}`);
    const warningData = data[`warning_${windowInfo.id}`];
    
    if (!warningData) {
      throw new Error('Warning data not found');
    }

    const { targetUrl, analysis } = warningData;
    
    // Update UI elements
    document.getElementById('targetUrl').textContent = targetUrl;
    
    const riskDetails = document.getElementById('riskDetails');
    riskDetails.innerHTML = `
      <div class="risk-summary">
        <p>Risk Score: <span class="risk-score ${getRiskClass(analysis.urlDetails.riskScore)}">
          ${analysis.urlDetails.riskScore}%
        </span></p>
        <p>Threat Level: ${analysis.urlDetails.threatLevel}</p>
        ${analysis.urlDetails.flags.length > 0 ? `
          <div class="risk-factors">
            <h4>Risk Factors:</h4>
            <ul>
              ${analysis.urlDetails.flags.map(flag => `<li>${flag}</li>`).join('')}
            </ul>
          </div>
        ` : ''}
      </div>
    `;

    const warningDialog = document.getElementById('warningDialog');
    
    // Add color-coded risk level
    warningDialog.classList.add(getRiskClass(analysis.urlDetails.riskScore));

    // Setup button handlers
    document.getElementById('proceedBtn').addEventListener('click', () => {
      chrome.runtime.sendMessage({ 
        action: 'proceedToUrl', 
        url: targetUrl 
      });
    });

    document.getElementById('cancelBtn').addEventListener('click', () => {
      window.close();
    });

    document.getElementById('reportBtn').addEventListener('click', async () => {
      try {
        const response = await chrome.runtime.sendMessage({
          action: 'reportPhish',
          url: targetUrl,
          details: {
            riskScore: analysis.urlDetails.riskScore,
            threatLevel: analysis.urlDetails.threatLevel,
            reportedFlags: analysis.urlDetails.flags
          }
        });

        if (response.success) {
          alert('Thank you for your report. This helps protect other users.');
          window.close();
        } else {
          throw new Error(response.message);
        }
      } catch (error) {
        console.error('Failed to submit report:', error);
        alert('Failed to submit report. Please try again later.');
      }
    });

    // Clean up stored data
    chrome.storage.local.remove(`warning_${windowInfo.id}`);

  } catch (error) {
    console.error('Warning dialog error:', error);
    document.body.innerHTML = `
      <div class="error-message">
        <h3>Error Loading Warning</h3>
        <p>${error.message}</p>
        <button onclick="window.close()">Close</button>
      </div>
    `;
  }
});

function getRiskClass(score) {
  if (score >= 75) return 'high-risk';
  if (score >= 50) return 'medium-risk';
  return 'low-risk';
}
