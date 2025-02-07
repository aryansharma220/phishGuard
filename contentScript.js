// Listen for DOM mutations to detect dynamic content changes
const observer = new MutationObserver((mutations) => {
  mutations.forEach((mutation) => {
    if (mutation.type === 'childList') {
      checkForSuspiciousContent();
      findAndProcessLinks();
    }
  });
});

// Start observing the document
observer.observe(document.body, {
  childList: true,
  subtree: true
});

// Check for suspicious content in the page
function checkForSuspiciousContent() {
  const analysis = {
    forms: analyzeFormElements(),
    links: analyzeLinks(),
    scripts: analyzeScripts(),
    content: analyzePageContent()
  };

  if (hasHighRiskIndicators(analysis)) {
    notifyBackground({
      type: 'high_risk',
      message: 'High-risk elements detected',
      url: window.location.href,
      analysis
    });
  }
}

// Analyze form elements
function analyzeFormElements() {
  const forms = document.querySelectorAll('form');
  return Array.from(forms).map(form => ({
    action: form.action,
    method: form.method,
    hasPasswordField: !!form.querySelector('input[type="password"]'),
    hasEmailField: !!form.querySelector('input[type="email"]'),
    submitUrl: new URL(form.action || window.location.href).hostname,
    isCrossDomain: form.action && new URL(form.action).hostname !== window.location.hostname
  }));
}

// Analyze links
function analyzeLinks() {
  return Array.from(document.links).map(link => ({
    href: link.href,
    text: link.textContent,
    isExternal: link.hostname !== window.location.hostname,
    isSuspicious: checkSuspiciousLink(link),
    hasDeceptiveText: checkDeceptiveText(link)
  }));
}

// Analyze scripts
function analyzeScripts() {
  return Array.from(document.scripts).map(script => ({
    src: script.src,
    isExternal: script.src && new URL(script.src).hostname !== window.location.hostname,
    containsSuspiciousCode: checkScriptContent(script)
  }));
}

// Analyze page content
function analyzePageContent() {
  return {
    hasObfuscatedContent: checkForObfuscation(),
    hasSensitiveInputs: checkForSensitiveInputs(),
    hasDeceptiveBranding: checkForDeceptiveBranding(),
    securityIndicators: checkSecurityIndicators()
  };
}

// Enhanced link detection
function findAndProcessLinks() {
  const processedLinks = new Set();
  
  // Process all links
  document.querySelectorAll('a[href^="http"]:not(.phishguard-processed)').forEach(link => {
    if (!processedLinks.has(link.href)) {
      processedLinks.add(link.href);
      wrapLinkElement(link);
    }
  });

  // Process onclick attributes
  document.querySelectorAll('[onclick]:not(.phishguard-processed)').forEach(element => {
    const matches = element.getAttribute('onclick').match(/(?:location\.href|window\.location)\s*=\s*['"]([^'"]+)['"]/);
    if (matches && matches[1].startsWith('http')) {
      wrapLinkElement(element, matches[1]);
    }
  });
}

// Improved link wrapping
function wrapLinkElement(element, url = null) {
  try {
    if (element.classList.contains('phishguard-processed')) return;
    element.classList.add('phishguard-processed');

    const targetUrl = url || element.href;
    chrome.runtime.sendMessage({
      action: 'checkUrl',
      url: targetUrl
    }, response => {
      if (chrome.runtime.lastError) {
        console.error('Runtime error:', chrome.runtime.lastError);
        return;
      }

      if (response && !response.safe) {
        markDangerousLink(element, response, targetUrl);
      }
    });
  } catch (error) {
    console.error('Error processing link:', error);
  }
}

// Mark dangerous links
function markDangerousLink(element, analysis, url) {
  element.classList.add('phishguard-warning');
  element.style.cursor = 'help';

  // Create warning tooltip
  const tooltip = document.createElement('div');
  tooltip.className = 'phishguard-tooltip';
  tooltip.innerHTML = `
    <div class="tooltip-header">
      ⚠️ Warning: Potentially unsafe link
    </div>
    <div class="tooltip-content">
      Risk Score: ${analysis.urlDetails.riskScore}%
      <br>
      ${analysis.urlDetails.threatLevel} Risk Level
    </div>
  `;
  element.appendChild(tooltip);

  // Add click handler
  element.addEventListener('click', async (e) => {
    e.preventDefault();
    e.stopPropagation();
    
    try {
      const warningUrl = chrome.runtime.getURL('warningDialog.html') +
        `?url=${encodeURIComponent(url)}&analysis=${encodeURIComponent(JSON.stringify(analysis))}`;
      
      await chrome.runtime.sendMessage({
        action: 'openWarningDialog',
        warningUrl,
        originalUrl: url
      });
    } catch (error) {
      console.error('Error showing warning:', error);
      if (confirm('This link appears to be unsafe. Proceed anyway?')) {
        window.location.href = url;
      }
    }
  }, true);
}

// Send messages to background script
function notifyBackground(data) {
  chrome.runtime.sendMessage({
    action: 'contentAlert',
    data: data
  });
}

// Listen for messages from background script
chrome.runtime.onMessage.addListener((message, sender, sendResponse) => {
  if (message.action === 'analyzeContent') {
    const analysis = {
      forms: document.querySelectorAll('form').length,
      passwordFields: document.querySelectorAll('input[type="password"]').length,
      hiddenElements: document.querySelectorAll('[style*="opacity: 0"], [style*="display: none"]').length,
      externalLinks: Array.from(document.links).filter(link => {
        try {
          return new URL(link.href).origin !== window.location.origin;
        } catch {
          return false;
        }
      }).length
    };
    sendResponse(analysis);
  }
  return true;
});

// Initial check when script is loaded
checkForSuspiciousContent();
findAndProcessLinks();
