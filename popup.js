class PhishGuardUI {
  constructor() {
    this.currentUrl = '';
    this.analysisResult = null;
    this.retryCount = 0;
    this.maxRetries = 3;
    this.updateInterval = null;
    this.lastAnalysis = null;
  }

  async init() {
    try {
      await this.getCurrentTab();
      this.setupEventListeners();
      await this.startAnalysis();
      this.setupAutoUpdate();
    } catch (error) {
      this.handleError(error);
    }
  }

  async getCurrentTab() {
    const tabs = await chrome.tabs.query({ active: true, currentWindow: true });
    if (!tabs[0]?.url) {
      throw new Error('No valid URL found');
    }
    this.currentUrl = tabs[0].url;
    this.updateUrlDisplay();
  }

  setupEventListeners() {
    document.getElementById('refreshAnalysis').addEventListener('click', () => {
      this.startAnalysis();
    });

    // Add tab switching listeners
    document.querySelectorAll('.tab-btn').forEach(btn => {
      btn.addEventListener('click', (e) => {
        this.switchTab(e.target.dataset.tab);
      });
    });

    // Add detailed report listener
    document.getElementById('detailedReport').addEventListener('click', () => {
      this.showDetailedReport();
    });

    // Add report phishing button handler
    document.getElementById('reportPhishingBtn').addEventListener('click', () => {
      this.reportPhishing();
    });
  }

  setupAutoUpdate() {
    // Update analysis every 5 minutes
    this.updateInterval = setInterval(() => {
      if (document.visibilityState === 'visible') {
        this.startAnalysis(true);
      }
    }, 5 * 60 * 1000);
  }

  async startAnalysis(silent = false) {
    if (!silent) {
      this.showLoadingState();
    }

    try {
      const analysis = await this.performAnalysis();
      if (!analysis) throw new Error('Analysis failed');

      // Compare with last analysis
      const changes = this.compareAnalysis(analysis);
      this.updateUI(analysis, changes);
      this.lastAnalysis = analysis;
    } catch (error) {
      await this.handleAnalysisError(error);
    }
  }

  async performAnalysis() {
    return new Promise((resolve, reject) => {
      chrome.runtime.sendMessage({ 
        action: 'checkUrl', 
        url: this.currentUrl 
      }, response => {
        if (chrome.runtime.lastError) {
          reject(chrome.runtime.lastError);
        } else {
          resolve(response);
        }
      });
    });
  }

  compareAnalysis(newAnalysis) {
    if (!this.lastAnalysis) return null;

    return {
      riskScoreChanged: newAnalysis.urlDetails.riskScore !== this.lastAnalysis.urlDetails.riskScore,
      newFlags: newAnalysis.urlDetails.flags.filter(flag => 
        !this.lastAnalysis.urlDetails.flags.includes(flag)
      ),
      removedFlags: this.lastAnalysis.urlDetails.flags.filter(flag => 
        !newAnalysis.urlDetails.flags.includes(flag)
      )
    };
  }

  handleError(error) {
    console.error('PhishGuard Error:', error);
    this.showError(`${error.message}\nPlease try again or contact support if the problem persists.`);
  }

  async handleAnalysisError(error) {
    if (this.retryCount < this.maxRetries) {
      this.retryCount++;
      await new Promise(resolve => setTimeout(resolve, 1000 * this.retryCount));
      return this.startAnalysis();
    }
    this.handleError(error);
  }

  updateUrlDisplay() {
    const urlDisplay = document.getElementById('currentUrl');
    urlDisplay.textContent = this.currentUrl;
    urlDisplay.title = this.currentUrl;
  }

  showLoadingState() {
    document.getElementById('analysisStatus').style.display = 'flex';
    document.getElementById('resultsContainer').style.display = 'none';
  }

  showError(message) {
    const errorDiv = document.getElementById('analysisStatus');
    errorDiv.innerHTML = `
      <div class="error-message">
        <span class="error-icon">❌</span>
        <span>${message}</span>
        <button onclick="location.reload()">Retry</button>
      </div>
    `;
    errorDiv.style.display = 'block';
  }

  updateUI(analysis, changes = null) {
    try {
      document.getElementById('analysisStatus').style.display = 'none';
      document.getElementById('resultsContainer').style.display = 'block';
      
      this.analysisResult = analysis; // Store for detailed report
      this.updateRiskScore(analysis.urlDetails.riskScore);
      this.updateSecurityChecks(analysis);
      this.updateTechnicalDetails(analysis);
      this.updateAIAnalysis(analysis);
      
      document.getElementById('lastUpdated').textContent = new Date().toLocaleTimeString();

      // Show changes if any
      if (changes && (changes.newFlags.length > 0 || changes.removedFlags.length > 0)) {
        this.showChangesNotification(changes);
      }

      // Add reported status if URL was reported
      chrome.storage.local.get('phishingReports', (data) => {
        const reports = data.phishingReports || [];
        const reported = reports.some(report => report.url === this.currentUrl);
        if (reported) {
          const reportBadge = document.createElement('div');
          reportBadge.className = 'report-badge';
          reportBadge.textContent = '⚠️ Reported as Phishing';
          document.getElementById('resultsContainer').prepend(reportBadge);
        }
      });

      // Update report button state if URL was already reported
      chrome.storage.local.get('phishingReports', (data) => {
        const reports = data.phishingReports || [];
        const reported = reports.some(report => report.url === this.currentUrl);
        
        const reportBtn = document.getElementById('reportPhishingBtn');
        if (reported) {
          reportBtn.textContent = '✓ Reported as Phishing';
          reportBtn.disabled = true;
          reportBtn.style.background = '#6c757d';
        } else {
          reportBtn.textContent = '🚫 Report Phishing Website';
          reportBtn.disabled = false;
          reportBtn.style.background = '';
        }
      });

    } catch (error) {
      this.handleError(error);
    }
  }

  updateRiskScore(score) {
    const riskScore = document.getElementById('riskScore');
    const riskLabel = document.getElementById('riskLabel');
    
    riskScore.textContent = `${score}%`;
    riskLabel.textContent = this.getRiskLevel(score);
    riskLabel.className = `risk-label ${this.getRiskClass(score)}`;
  }

  getRiskLevel(score) {
    if (score >= 75) return 'Critical Risk';
    if (score >= 50) return 'High Risk';
    if (score >= 25) return 'Medium Risk';
    return 'Low Risk';
  }

  getRiskClass(score) {
    if (score >= 75) return 'risk-critical';
    if (score >= 50) return 'risk-high';
    if (score >= 25) return 'risk-medium';
    return 'risk-low';
  }

  updateSecurityChecks(analysis) {
    const container = document.getElementById('securityChecks');
    container.innerHTML = this.generateSecurityChecksList(analysis);
  }

  updateTechnicalDetails(analysis) {
    const container = document.getElementById('technicalDetails');
    if (!container) return;

    const details = analysis.urlDetails.technicalDetails || {};
    const metrics = [
      {
        label: 'Domain Trust',
        score: Math.round(100 - (details.domainTrustScore || 0)),
        class: this.getRiskClass(details.domainTrustScore || 0)
      },
      {
        label: 'AI Confidence',
        score: Math.round(details.aiConfidence || 0),
        class: this.getRiskClass(100 - (details.aiConfidence || 0))
      },
      {
        label: 'ML Detection',
        score: Math.round(details.mlDetectionScore || 0),
        class: this.getRiskClass(details.mlDetectionScore || 0)
      },
      {
        label: 'Content Risk',
        score: Math.round(details.contentRiskScore || 0),
        class: this.getRiskClass(details.contentRiskScore || 0)
      }
    ];

    const indicators = details.indicators || {};
    const indicatorsList = Object.entries(indicators)
      .filter(([, detected]) => detected)
      .map(([key]) => this.formatIndicatorName(key))
      .join('</li><li>');

    container.innerHTML = `
      <div class="metrics-grid">
        ${metrics.map(metric => `
          <div class="metric-item ${metric.class}">
            <div class="metric-label">${metric.label}</div>
            <div class="metric-score">${metric.score}%</div>
          </div>
        `).join('')}
      </div>
      ${indicatorsList ? `
        <div class="risk-indicators">
          <h4>Risk Indicators Found:</h4>
          <ul>
            <li>${indicatorsList}</li>
          </ul>
        </div>
      ` : ''}
    `;
  }

  updateAIAnalysis(analysis) {
    const container = document.getElementById('aiInsights');
    if (!container) return;

    const aiData = {
      geminiAnalysis: analysis.geminiDetails || 'No AI analysis available',
      confidence: analysis.confidence || 0,
      mlPrediction: analysis.urlDetails.technicalDetails?.mlDetectionScore || 0,
      riskFactors: analysis.urlDetails.flags || []
    };

    container.innerHTML = `
      <div class="ai-analysis-container">
        <div class="ai-confidence">
          <div class="confidence-score ${this.getRiskClass(aiData.confidence)}">
            ${aiData.confidence}%
          </div>
          <div class="confidence-label">AI Confidence</div>
        </div>
        
        <div class="ai-explanation">
          <h4>AI Analysis:</h4>
          <p>${aiData.geminiAnalysis}</p>
        </div>
        
        ${aiData.riskFactors.length > 0 ? `
          <div class="risk-factors">
            <h4>Detected Risk Factors:</h4>
            <ul>
              ${aiData.riskFactors.map(factor => `<li>${factor}</li>`).join('')}
            </ul>
          </div>
        ` : ''}
      </div>
    `;
  }

  async showDetailedReport() {
    if (!this.analysisResult) return;

    const reportData = {
      url: this.currentUrl,
      timestamp: new Date().toISOString(),
      analysis: this.analysisResult
    };

    try {
      // Create a detailed report window
      const reportWindow = window.open('', '_blank', 'width=800,height=600');
      reportWindow.document.write(`
        <!DOCTYPE html>
        <html>
        <head>
          <title>Detailed Security Report - PhishGuard</title>
          <style>
            body { font-family: 'Inter', sans-serif; margin: 0; padding: 20px; }
            .report-container { max-width: 800px; margin: 0 auto; }
            .section { margin-bottom: 24px; }
            .section h2 { color: #2962ff; }
            .data-table { width: 100%; border-collapse: collapse; margin: 12px 0; }
            .data-table th, .data-table td { 
              padding: 8px; 
              border: 1px solid #dee2e6; 
              text-align: left; 
            }
            .risk-high { background: #ffebee; color: #c62828; }
            .risk-medium { background: #fff3cd; color: #856404; }
            .risk-low { background: #e8f5e9; color: #2e7d32; }
          </style>
        </head>
        <body>
          <div class="report-container">
            <h1>PhishGuard Security Report</h1>
            <div class="section">
              <h2>URL Information</h2>
              <p>Analyzed URL: ${this.currentUrl}</p>
              <p>Analysis Time: ${new Date().toLocaleString()}</p>
            </div>

            <div class="section">
              <h2>Risk Assessment</h2>
              <table class="data-table">
                <tr>
                  <th>Risk Score</th>
                  <td class="${this.getRiskClass(reportData.analysis.urlDetails.riskScore)}">
                    ${reportData.analysis.urlDetails.riskScore}%
                  </td>
                </tr>
                <tr>
                  <th>Threat Level</th>
                  <td>${reportData.analysis.urlDetails.threatLevel}</td>
                </tr>
                <tr>
                  <th>AI Confidence</th>
                  <td>${reportData.analysis.confidence}%</td>
                </tr>
              </table>
            </div>

            <div class="section">
              <h2>Technical Details</h2>
              <table class="data-table">
                ${Object.entries(reportData.analysis.urlDetails.technicalDetails || {})
                  .map(([key, value]) => `
                    <tr>
                      <th>${this.formatIndicatorName(key)}</th>
                      <td>${typeof value === 'object' ? JSON.stringify(value) : value}</td>
                    </tr>
                  `).join('')}
              </table>
            </div>

            <div class="section">
              <h2>Security Checks</h2>
              <ul>
                ${reportData.analysis.urlDetails.flags.map(flag => 
                  `<li>${flag}</li>`
                ).join('')}
              </ul>
            </div>

            <div class="section">
              <h2>AI Analysis</h2>
              <p>${reportData.analysis.geminiDetails}</p>
            </div>
          </div>
        </body>
        </html>
      `);
      reportWindow.document.close();
    } catch (error) {
      console.error('Error generating detailed report:', error);
      this.showError('Failed to generate detailed report');
    }
  }

  generateSecurityChecksList(analysis) {
    const checks = [
      {
        name: 'Safe Browsing',
        passed: analysis.safe,
        details: analysis.safeBrowsingDetails
      },
      {
        name: 'Domain Age',
        passed: analysis.urlDetails.domainAge !== '1 week',
        details: `Domain age: ${analysis.urlDetails.domainAge}`
      },
      {
        name: 'SSL Certificate',
        passed: analysis.urlDetails.ssl === 'Valid SSL',
        details: analysis.urlDetails.ssl
      },
      {
        name: 'AI Risk Assessment',
        passed: analysis.confidence > 80,
        details: analysis.geminiDetails
      }
    ];

    return checks.map(check => `
      <div class="security-check">
        <div class="check-icon ${check.passed ? 'pass' : 'fail'}">
          ${check.passed ? '✓' : '✕'}
        </div>
        <div class="check-details">
          <div class="check-name">${check.name}</div>
          <div class="check-info">${check.details}</div>
        </div>
      </div>
    `).join('');
  }

  formatIndicatorName(key) {
    return key
      .replace(/([A-Z])/g, ' $1')
      .replace(/^./, str => str.toUpperCase())
      .replace(/has/g, '')
      .trim();
  }

  switchTab(tabId) {
    document.querySelectorAll('.tab-btn').forEach(btn => {
      btn.classList.toggle('active', btn.dataset.tab === tabId);
    });
    
    document.querySelectorAll('.tab-pane').forEach(pane => {
      pane.classList.toggle('active', pane.id === `${tabId}Tab`);
    });
  }

  showChangesNotification(changes) {
    const notification = document.createElement('div');
    notification.className = 'changes-notification';
    notification.innerHTML = `
      ${changes.newFlags.length > 0 ? `
        <div class="new-flags">
          <h4>New Risk Factors:</h4>
          <ul>${changes.newFlags.map(flag => `<li>${flag}</li>`).join('')}</ul>
        </div>
      ` : ''}
      ${changes.removedFlags.length > 0 ? `
        <div class="removed-flags">
          <h4>Resolved Issues:</h4>
          <ul>${changes.removedFlags.map(flag => `<li>${flag}</li>`).join('')}</ul>
        </div>
      ` : ''}
    `;
    
    document.getElementById('resultsContainer').prepend(notification);
    
    // Auto-remove notification after 5 seconds
    setTimeout(() => {
      notification.remove();
    }, 5000);
  }

  async reportPhishing() {
    try {
      const response = await chrome.runtime.sendMessage({
        action: 'reportPhish',
        url: this.currentUrl,
        details: {
          riskScore: this.analysisResult?.urlDetails?.riskScore || 100,
          threatLevel: this.analysisResult?.urlDetails?.threatLevel || 'Reported',
          reportedFlags: this.analysisResult?.urlDetails?.flags || ['User-reported phishing site']
        }
      });

      if (response.success) {
        // Update UI to show reported status
        const reportBtn = document.getElementById('reportPhishingBtn');
        reportBtn.textContent = '✓ Reported as Phishing';
        reportBtn.disabled = true;
        reportBtn.style.background = '#6c757d';
        
        // Show confirmation message
        this.showNotification('Thank you for reporting! This helps protect other users.', 'success');
        
        // Refresh analysis after short delay
        setTimeout(() => this.startAnalysis(), 1500);
      } else {
        throw new Error(response.message);
      }
    } catch (error) {
      this.showNotification('Failed to submit report. Please try again.', 'error');
      console.error('Report submission failed:', error);
    }
  }

  showNotification(message, type = 'info') {
    const notification = document.createElement('div');
    notification.className = `notification ${type}`;
    notification.textContent = message;
    document.querySelector('.container').prepend(notification);
    
    setTimeout(() => notification.remove(), 5000);
  }
}

// Initialize when document is loaded
document.addEventListener('DOMContentLoaded', () => {
  const ui = new PhishGuardUI();
  ui.init().catch(error => {
    console.error('Initialization failed:', error);
  });
});
