// Listen for DOM mutations to detect dynamic content changes
const observer = new MutationObserver((mutations) => {
  mutations.forEach((mutation) => {
    if (mutation.type === 'childList') {
      checkForSuspiciousContent();
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

  // Add click handler for links
  analysis.links.forEach(link => {
    const linkElement = document.querySelector(`a[href="${link.href}"]`);
    if (linkElement) {
      wrapLinkElement(linkElement, link);
    }
  });
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

// Add new helper functions...

// Add click handler for links
function wrapLinkElement(node, analysis) {
  if (!node.classList.contains('phishguard-warning')) {
    node.className += ' phishguard-warning';
    
    // Add click handler
    node.addEventListener('click', async (e) => {
      e.preventDefault();
      e.stopPropagation();
      
      // Show warning dialog
      const dialogWidth = 550;
      const dialogHeight = 400;
      const left = (window.screen.width - dialogWidth) / 2;
      const top = (window.screen.height - dialogHeight) / 2;

      const warningUrl = chrome.runtime.getURL('warningDialog.html') +
        `?url=${encodeURIComponent(node.href)}&analysis=${encodeURIComponent(JSON.stringify(analysis))}`;

      window.open(
        warningUrl,
        'phishguard_warning',
        `width=${dialogWidth},height=${dialogHeight},left=${left},top=${top}`
      );
    }, true);

    // Add tooltip
    const tooltip = document.createElement('div');
    tooltip.className = 'phishguard-tooltip';
    tooltip.innerHTML = `
      ⚠️ Warning: This link may be unsafe
      <br>
      Risk Score: ${analysis.urlDetails.riskScore}%
      <br>
      ${analysis.message}
    `;
    node.appendChild(tooltip);
  }
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
