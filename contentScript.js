// URL detection patterns
const URL_PATTERNS = {
  general: /https?:\/\/[^\s<>"']+/gi,
  shortened: /https?:\/\/(bit\.ly|tinyurl\.com|goo\.gl|t\.co|tiny\.cc|is\.gd|cli\.gs|pic\.gd|DwarfURL\.com|ow\.ly|yfrog|migre\.me|ff\.im|tiny\.cc|url4\.eu|twit\.ac|su\.pr|twurl\.nl|snipurl\.com|short\.to|BudURL\.com|ping\.fm|post\.ly|Just\.as|bkite\.com|snipr\.com|fic\.kr|loopt\.us|doiop\.com|short\.ie|kl\.am|wp\.me|rubyurl\.com|om\.ly|to\.ly|bit\.do|t\.co|lnkd\.in|db\.tt|qr\.ae|adf\.ly|goo\.gl|bitly\.com|cur\.lv|tinyurl\.com|ow\.ly|bit\.ly|ity\.im|q\.gs|is\.gd|po\.st|bc\.vc|twitthis\.com|u\.to|j\.mp|buzurl\.com|cutt\.us|u\.bb|yourls\.org|x\.co|prettylinkpro\.com|scrnch\.me|filoops\.info|vzturl\.com|qr\.net|1url\.com|tweez\.me|v\.gd|tr\.im|link\.zip\.net)[^\s<>"']+/gi
};

// Create styles for link indicators
const style = document.createElement('style');
style.textContent = `
  .phishguard-warning {
    position: relative !important;
    border-bottom: 2px dashed #ff4444 !important;
  }
  .phishguard-tooltip {
    position: absolute;
    background: #fff;
    border: 1px solid #ddd;
    padding: 8px;
    border-radius: 4px;
    box-shadow: 0 2px 4px rgba(0,0,0,0.2);
    z-index: 10000;
    max-width: 250px;
    font-size: 12px;
    display: none;
  }
  .phishguard-warning:hover .phishguard-tooltip {
    display: block;
  }
`;
document.head.appendChild(style);

// Initialize a Map to store analysis results
const urlAnalysisCache = new Map();

// Create and configure MutationObserver
const observer = new MutationObserver((mutations) => {
  mutations.forEach((mutation) => {
    scanForUrls(mutation.target);
  });
});

// Start observing the document with configured parameters
observer.observe(document.body, {
  childList: true,
  subtree: true,
  characterData: true,
  attributes: true,
  attributeFilter: ['href', 'src']
});

// Main URL scanning function
async function scanForUrls(node) {
  if (node.nodeType === Node.TEXT_NODE) {
    processTextNode(node);
  } else if (node.nodeType === Node.ELEMENT_NODE) {
    processElementNode(node);
  }
}

// Process text nodes for URLs
async function processTextNode(node) {
  const text = node.textContent;
  let match;
  
  // Check for URLs in text content
  for (const [patternType, pattern] of Object.entries(URL_PATTERNS)) {
    pattern.lastIndex = 0; // Reset regex state
    while ((match = pattern.exec(text)) !== null) {
      const url = match[0];
      await processUrl(url, node, match.index);
    }
  }
}

// Process element nodes for URLs
async function processElementNode(node) {
  // Skip if the node is our own tooltip or already processed
  if (node.classList?.contains('phishguard-tooltip') || 
      node.classList?.contains('phishguard-warning')) {
    return;
  }

  // Check anchor tags
  if (node.tagName === 'A' && node.href) {
    await processUrl(node.href, node);
  }

  // Check elements with onclick handlers containing URLs
  const onclickAttr = node.getAttribute('onclick');
  if (onclickAttr) {
    for (const [, pattern] of Object.entries(URL_PATTERNS)) {
      pattern.lastIndex = 0;
      const matches = onclickAttr.match(pattern);
      if (matches) {
        for (const url of matches) {
          await processUrl(url, node);
        }
      }
    }
  }
}

// Process individual URLs
async function processUrl(url, node, textIndex = null) {
  // Skip if already cached as safe
  if (urlAnalysisCache.has(url) && urlAnalysisCache.get(url).safe) {
    return;
  }

  try {
    // Check cache first
    let analysis = urlAnalysisCache.get(url);
    if (!analysis) {
      // Request analysis from background script
      analysis = await chrome.runtime.sendMessage({
        action: 'checkUrl',
        url: url
      });
      urlAnalysisCache.set(url, analysis);
    }

    if (!analysis.safe) {
      markSuspiciousUrl(url, node, textIndex, analysis);
    }
  } catch (error) {
    console.error('Error analyzing URL:', url, error);
  }
}

// Mark suspicious URLs in the page
function markSuspiciousUrl(url, node, textIndex, analysis) {
  if (node.nodeType === Node.TEXT_NODE && textIndex !== null) {
    wrapTextNodeUrl(node, url, textIndex, analysis);
  } else if (node.tagName === 'A') {
    wrapLinkElement(node, analysis);
  } else {
    wrapElement(node, analysis);
  }
}

// Helper function to wrap text node URLs
function wrapTextNodeUrl(node, url, index, analysis) {
  const text = node.textContent;
  const wrapper = document.createElement('span');
  wrapper.className = 'phishguard-warning';
  
  const before = text.substring(0, index);
  const after = text.substring(index + url.length);
  
  wrapper.innerHTML = `
    ${url}
    <div class="phishguard-tooltip">
      ⚠️ Warning: This link may be unsafe
      <br>
      Risk Score: ${analysis.urlDetails.riskScore}%
      <br>
      ${analysis.message}
    </div>
  `;

  const fragment = document.createDocumentFragment();
  if (before) fragment.appendChild(document.createTextNode(before));
  fragment.appendChild(wrapper);
  if (after) fragment.appendChild(document.createTextNode(after));
  
  node.parentNode.replaceChild(fragment, node);
}

// Helper function to wrap link elements
function wrapLinkElement(node, analysis) {
  if (!node.classList.contains('phishguard-warning')) {
    node.className += ' phishguard-warning';
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

// Helper function to wrap other elements
function wrapElement(node, analysis) {
  const wrapper = document.createElement('span');
  wrapper.className = 'phishguard-warning';
  node.parentNode.insertBefore(wrapper, node);
  wrapper.appendChild(node);
  
  const tooltip = document.createElement('div');
  tooltip.className = 'phishguard-tooltip';
  tooltip.innerHTML = `
    ⚠️ Warning: This link may be unsafe
    <br>
    Risk Score: ${analysis.urlDetails.riskScore}%
    <br>
    ${analysis.message}
  `;
  wrapper.appendChild(tooltip);
}

// Initial scan of the page
scanForUrls(document.body);

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

// Add new helper functions...

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
