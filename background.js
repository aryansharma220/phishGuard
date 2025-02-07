let ENV_VARS = {};

// Load environment variables at startup
async function loadEnvVars() {
  try {
    const response = await fetch(chrome.runtime.getURL('.env'));
    const text = await response.text();
    ENV_VARS = text.split('\n').reduce((acc, line) => {
      const [key, value] = line.split('=').map(s => s.trim());
      if (key && value) {
        acc[key] = value;
      }
      return acc;
    }, {});
    console.log('Environment variables loaded:', ENV_VARS);
  } catch (error) {
    console.error('Failed to load environment variables:', error);
  }
}

// Initialize environment variables immediately
loadEnvVars();

chrome.runtime.onMessage.addListener((request, sender, sendResponse) => {
  if (request.action === 'checkUrl') {
    handleUrlCheck(request.url)
      .then(sendResponse)
      .catch(error => {
        console.error('URL check error:', error);
        sendResponse({
          safe: false,
          error: error.message,
          urlDetails: {
            riskScore: 100,
            threatLevel: 'Error',
            flags: ['Analysis failed: ' + error.message]
          }
        });
      });
    return true;
  }

  if (request.action === 'openWarningDialog') {
    // Create popup window with centered position
    const width = 500;
    const height = 600;
    const left = Math.round((screen.width - width) / 2);
    const top = Math.round((screen.height - height) / 2);

    chrome.windows.create({
      url: request.warningUrl,
      type: 'popup',
      width: width,
      height: height,
      left: left,
      top: top,
      focused: true
    }).then(window => {
      // Store the target URL for this warning window
      chrome.storage.local.set({
        [`warning_${window.id}`]: {
          targetUrl: request.originalUrl,
          analysis: request.analysis
        }
      });
      sendResponse({ success: true });
    }).catch(error => {
      console.error('Failed to open warning dialog:', error);
      sendResponse({ error: error.message });
    });
    return true;
  }

  if (request.action === 'proceedToUrl') {
    chrome.tabs.create({ url: request.url }, () => {
      // Close the warning window after proceeding
      if (sender.tab) {
        chrome.windows.remove(sender.tab.windowId);
      }
    });
    return true;
  }

  if (request.action === 'reportPhish') {
    handlePhishReport(request.url, request.details)
      .then(response => sendResponse({ success: true, message: 'Report submitted successfully' }))
      .catch(error => sendResponse({ success: false, message: error.message }));
    return true;
  }
});

// Add message handler for proceeding to URL
chrome.runtime.onMessage.addListener((request, sender, sendResponse) => {
  if (request.action === 'proceedToUrl') {
    chrome.tabs.create({ url: request.url });
    return true;
  }
  // ...existing message handlers...
});

// Add new cache system
const urlCache = new Map();
const CACHE_DURATION = 30 * 60 * 1000; // 30 minutes

// Add rate limiting
const rateLimiter = {
  requests: new Map(),
  limit: 100,
  interval: 60 * 1000, // 1 minute
  checkLimit(key) {
    const now = Date.now();
    const requests = this.requests.get(key) || [];
    const validRequests = requests.filter(time => time > now - this.interval);
    this.requests.set(key, validRequests);
    return validRequests.length < this.limit;
  },
  addRequest(key) {
    const requests = this.requests.get(key) || [];
    requests.push(Date.now());
    this.requests.set(key, requests);
  }
};

// Improve URL check with caching
async function handleUrlCheck(url) {
  try {
    const startTime = Date.now();

    // Check cache first
    const cached = urlCache.get(url);
    if (cached && Date.now() - cached.timestamp < CACHE_DURATION) {
      return cached.result;
    }

    // Check rate limit
    if (!rateLimiter.checkLimit(url)) {
      throw new Error('Rate limit exceeded');
    }
    rateLimiter.addRequest(url);

    const result = await checkUrl(url);
    
    // Cache the result
    urlCache.set(url, {
      timestamp: Date.now(),
      result
    });

    const endTime = Date.now();
    console.log(`URL check completed in ${endTime - startTime}ms:`, {
      url,
      result
    });

    return result;
  } catch (error) {
    console.error('URL check failed:', error);
    throw error;
  }
}

async function checkUrl(url) {
  try {
    const urlInfo = new URL(url);
    
    // Enhanced parallel checks with confidence scores
    const [safeBrowsingResult, geminiResult, domainInfo, mlAnalysis, contentAnalysis] = await Promise.all([
      checkSafeBrowsing(url),
      checkGemini(url, urlInfo),
      analyzeDomain(urlInfo),
      checkWithHuggingFace(url),
      analyzeUrlContent(url)
    ]);

    // Calculate confidence-weighted scores
    const scores = {
      safeBrowsing: safeBrowsingResult.safe ? 0 : 100,
      gemini: calculateGeminiScore(geminiResult),
      domain: calculateDomainScore(domainInfo),
      ml: mlAnalysis.score,
      content: contentAnalysis.score
    };

    const totalScore = calculateWeightedScore(scores);
    
    // Enhanced safety determination with multiple factors
    const isSafe = totalScore < 60 && 
                   safeBrowsingResult.safe && 
                   !contentAnalysis.hasPhishingIndicators &&
                   domainInfo.age !== '1 week' &&
                   mlAnalysis.score < 70;

    return {
      safe: isSafe,
      confidence: calculateConfidenceScore(scores, safeBrowsingResult, mlAnalysis),
      message: generateDetailedMessage(isSafe, scores),
      safeBrowsingDetails: safeBrowsingResult.details,
      geminiDetails: geminiResult.explanation,
      urlDetails: {
        domainAge: domainInfo.age,
        ssl: domainInfo.ssl,
        riskScore: totalScore,
        threatLevel: getThreatLevel(totalScore),
        technicalDetails: generateTechnicalReport(scores, contentAnalysis),
        flags: generateDetailedFlags(safeBrowsingResult, geminiResult, domainInfo, contentAnalysis, mlAnalysis)
      }
    };
  } catch (error) {
    console.error('URL check error:', error);
    throw error;
  }
}

async function checkSafeBrowsing(url) {
  try {
    const response = await fetch(`https://safebrowsing.googleapis.com/v4/threatMatches:find?key=${ENV_VARS.SAFE_BROWSING_API_KEY}`, {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({
        client: { clientId: 'phishing-detector', clientVersion: '1.0.0' },
        threatInfo: {
          threatTypes: ['MALWARE', 'SOCIAL_ENGINEERING'],
          platformTypes: ['ANY_PLATFORM'],
          threatEntryTypes: ['URL'],
          threatEntries: [{ url }]
        }
      })
    });

    if (!response.ok) {
      throw new Error('Safe Browsing API request failed');
    }

    const data = await response.json();
    return {
      safe: !data.matches,
      details: data.matches ? 
        `Threats detected: ${data.matches.map(m => m.threatType).join(', ')}` :
        'No known threats detected'
    };
  } catch (error) {
    console.error('Safe Browsing API error:', error);
    throw error;
  }
}

async function checkGemini(url, urlInfo) {
  try {
    const promptText = `Analyze this URL for phishing: ${url}\nConsider domain: ${urlInfo.hostname}, path: ${urlInfo.pathname}, parameters: ${urlInfo.search}\nResponse format:\nVERDICT: (SAFE/UNSAFE)\nCONFIDENCE: (0-100)\nEXPLANATION: (brief reason)`;

    const response = await fetch(`https://generativelanguage.googleapis.com/v1beta/models/gemini-pro:generateContent?key=${ENV_VARS.GEMINI_API_KEY}`, {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({
        contents: [{ parts: [{ text: promptText }] }]
      })
    });

    if (!response.ok) {
      throw new Error('Gemini API request failed');
    }

    const data = await response.json();
    if (!data.candidates || !data.candidates[0]?.content?.parts[0]?.text) {
      throw new Error('Invalid Gemini API response');
    }

    const result = data.candidates[0].content.parts[0].text;
    console.log('Gemini response:', result); // Add logging
    const [verdict, confidence, explanation] = parseGeminiResponse(result);
    
    // Add validation
    if (!verdict || !confidence) {
      throw new Error('Invalid Gemini response format');
    }

    return {
      safe: verdict === 'SAFE' && parseInt(confidence) > 80,
      explanation: explanation || 'No detailed analysis available'
    };
  } catch (error) {
    console.error('Gemini API error:', error);
    return { 
      safe: false, 
      explanation: 'AI analysis failed: ' + (error.message || 'Unknown error') 
    };
  }
}

function parseGeminiResponse(response) {
  try {
    const lines = response.split('\n');
    let verdict = 'UNSAFE';
    let confidence = '0';
    let explanation = '';

    lines.forEach(line => {
      const trimmedLine = line.trim();
      if (trimmedLine.startsWith('VERDICT:')) {
        verdict = trimmedLine.split(':')[1].trim().toUpperCase();
      } else if (trimmedLine.startsWith('CONFIDENCE:')) {
        confidence = trimmedLine.split(':')[1].trim().replace(/[^0-9]/g, '');
      } else if (trimmedLine.startsWith('EXPLANATION:')) {
        explanation = trimmedLine.split(':').slice(1).join(':').trim();
      }
    });

    // Validate the parsed values
    if (!verdict || !confidence || !explanation) {
      throw new Error('Invalid response format');
    }

    return [
      verdict,
      confidence,
      explanation
    ];
  } catch (error) {
    console.error('Error parsing Gemini response:', error);
    return ['UNSAFE', '0', 'Failed to parse AI response'];
  }
}

// Add missing helper functions
function getThreatLevel(score) {
  if (score >= 75) return 'Critical';
  if (score >= 60) return 'High';
  if (score >= 40) return 'Medium';
  return 'Low';
}

function generateFlags(safeBrowsing, gemini, domain, riskScore) {
  const flags = [];
  if (!safeBrowsing.safe) flags.push('Detected by Safe Browsing API');
  if (!gemini.safe) flags.push('AI detected suspicious patterns');
  if (domain.age === 'Unknown' || domain.age === '1 week') flags.push('Recently registered domain');
  if (!domain.isSecure) flags.push('No SSL certificate');
  if (riskScore >= 75) flags.push('High risk score detected');
  return flags;
}

async function analyzeDomain(urlInfo) {
  try {
    const domain = urlInfo.hostname;
    const whoisData = await fetchWhoisData(domain);
    
    const analysis = {
      age: calculateDomainAge(whoisData.created_date),
      ssl: urlInfo.protocol === 'https:' ? 'Valid SSL' : 'No SSL',
      isSecure: urlInfo.protocol === 'https:',
      registrar: whoisData.registrar || 'Unknown',
      createdDate: whoisData.created_date || 'Unknown',
      expiryDate: whoisData.expiry_date || 'Unknown',
      updatedDate: whoisData.updated_date || 'Unknown',
      nameServers: whoisData.name_servers || [],
      registrantCountry: whoisData.registrant_country || 'Unknown',
      suspiciousPatterns: checkSuspiciousPatterns(domain),
      hasNumbers: /\d/.test(domain),
      specialChars: (domain.match(/[^a-zA-Z0-9.-]/g) || []).length,
      length: domain.length,
      subdomains: domain.split('.').length - 1
    };

    return {
      age: analysis.age,
      ssl: analysis.ssl,
      isSecure: analysis.isSecure,
      details: analysis
    };
  } catch (error) {
    console.error('Domain analysis error:', error);
    return {
      age: 'Unknown',
      ssl: urlInfo.protocol === 'https:' ? 'Valid SSL' : 'No SSL',
      isSecure: urlInfo.protocol === 'https:',
      details: {}
    };
  }
}

async function fetchWhoisData(domain) {
  try {
    const response = await fetch(`https://whois.whoisxmlapi.com/api/v1?apiKey=${ENV_VARS.WHOIS_API_KEY}&domainName=${domain}`);
    if (!response.ok) {
      throw new Error('WHOIS API request failed');
    }
    const data = await response.json();
    return {
      created_date: data.WhoisRecord?.createdDate,
      expiry_date: data.WhoisRecord?.expiryDate,
      updated_date: data.WhoisRecord?.updatedDate,
      registrar: data.WhoisRecord?.registrar?.name,
      name_servers: data.WhoisRecord?.nameServers?.hostNames || [],
      registrant_country: data.WhoisRecord?.registrant?.country,
    };
  } catch (error) {
    console.error('WHOIS API error:', error);
    return {};
  }
}

function calculateDomainAge(createdDate) {
  if (!createdDate) return 'Unknown';
  
  try {
    const created = new Date(createdDate);
    const now = new Date();
    const ageInDays = Math.floor((now - created) / (1000 * 60 * 60 * 24));
    
    if (ageInDays < 7) return '1 week';
    if (ageInDays < 30) return '1 month';
    if (ageInDays < 180) return '6 months';
    if (ageInDays < 365) return '1 year';
    return '5 years+';
  } catch {
    return 'Unknown';
  }
}

function calculateDomainScore(domainInfo) {
  let score = 0;
  const details = domainInfo.details || {};
  
  // Domain age scoring with graduated scale
  const ageScores = {
    '1 week': { score: 50, confidence: 0.9 },
    '1 month': { score: 40, confidence: 0.8 },
    '6 months': { score: 20, confidence: 0.7 },
    '1 year': { score: 10, confidence: 0.6 },
    '5 years+': { score: 0, confidence: 0.9 },
    'Unknown': { score: 35, confidence: 0.5 }
  };

  const ageScore = ageScores[domainInfo.age] || ageScores['Unknown'];
  score += ageScore.score * ageScore.confidence;

  // WHOIS data analysis
  if (details) {
    // Registrar reputation check
    const knownRegistrars = ['GoDaddy', 'Namecheap', 'Google Domains', 'Amazon Registrar'];
    if (!knownRegistrars.some(r => details.registrar?.toLowerCase().includes(r.toLowerCase()))) {
      score += 15;
    }

    // Name servers analysis
    if (!details.nameServers?.length) {
      score += 20;
    } else if (details.nameServers.length < 2) {
      score += 10;
    }

    // Registration country risk assessment
    const highRiskCountries = new Set([
      'unknown', '', null, undefined,
      // Add known high-risk countries based on cybersecurity reports
    ]);
    if (highRiskCountries.has(details.registrantCountry?.toLowerCase())) {
      score += 25;
    }

    // Pattern analysis with weighted scoring
    const suspiciousPatterns = checkSuspiciousPatterns(details.domain);
    score += suspiciousPatterns.reduce((total, { weight }) => total + weight, 0);

    // Technical indicators
    if (!domainInfo.isSecure) score += 30;
    if (details.hasNumbers) score += 10;
    score += (details.specialChars || 0) * 8;
    if (details.length > 30) score += 15;
    if (details.subdomains > 3) score += 20;
  }

  return Math.min(Math.round(score), 100);
}

async function checkWithHuggingFace(url) {
  try {
    const response = await fetch('https://api-inference.huggingface.co/models/ealvaradob/bert-finetuned-phishing', {
      method: 'POST',
      headers: {
        'Authorization': `Bearer ${ENV_VARS.HUGGING_FACE_API_KEY}`,
        'Content-Type': 'application/json'
      },
      body: JSON.stringify({ inputs: url })
    });

    const data = await response.json();
    return {
      score: data[0][0].score * 100,
      label: data[0][0].label
    };
  } catch (error) {
    console.error('ML analysis error:', error);
    return { score: 50, label: 'unknown' };
  }
}

async function analyzeUrlContent(url) {
  try {
    const response = await fetch(url);
    const text = await response.text();
    
    const indicators = {
      // Form analysis
      hasPasswordField: {
        detected: /<input[^>]*type=["']password["'][^>]*>/i.test(text),
        weight: 15
      },
      hasLoginForm: {
        detected: /<form[^>]*>[\s\S]*?(?:login|signin|password)[\s\S]*?<\/form>/i.test(text),
        weight: 20
      },
      
      // Script analysis
      hasSuspiciousRedirects: {
        detected: /window\.location\s*=|document\.location\s*=|setTimeout\s*\([^)]*(?:location|redirect|url)/i.test(text),
        weight: 25
      },
      hasObfuscatedCode: {
        detected: /(eval|unescape|escape|atob|btoa)\s*\([^)]*\)|(function\s*\(\s*\)\s*{\s*[a-z$_]{1,2})/i.test(text),
        weight: 30
      },
      
      // Content analysis
      hasDataExfiltration: {
        detected: /XMLHttpRequest|fetch\s*\(|navigator\.sendBeacon|websocket/i.test(text),
        weight: 20
      },
      hasSuspiciousHeaders: {
        detected: /<h[1-6][^>]*>\s*(?:verify|confirm|secure|account|login|password|bank|wallet)/i.test(text),
        weight: 15
      },
      
      // Hidden elements
      hasHiddenFields: {
        detected: /<[^>]+(?:visibility:\s*hidden|display:\s*none|opacity:\s*0)[^>]*>.*?(?:password|email|account|card)/i.test(text),
        weight: 25
      }
    };

    const score = Object.values(indicators).reduce((total, { detected, weight }) => {
      return total + (detected ? weight : 0);
    }, 0);

    return {
      score: Math.min(score, 100),
      hasPhishingIndicators: score > 40,
      indicators: Object.fromEntries(
        Object.entries(indicators).map(([key, { detected }]) => [key, detected])
      )
    };
  } catch (error) {
    console.error('Content analysis error:', error);
    return {
      score: 0,
      hasPhishingIndicators: false,
      indicators: {}
    };
  }
}

// Improve scoring algorithm
function calculateWeightedScore(scores) {
  // Dynamic weight adjustment based on confidence levels
  const weights = {
    safeBrowsing: 0.35,
    gemini: 0.15,
    domain: 0.25,
    ml: 0.15,
    content: 0.10
  };

  // Adjust weights based on confidence and reliability
  const adjustWeights = (scores) => {
    if (scores.safeBrowsing > 80) {
      weights.safeBrowsing += 0.15;
      weights.gemini -= 0.05;
      weights.ml -= 0.05;
      weights.content -= 0.05;
    }

    if (scores.ml > 90) {
      weights.ml += 0.10;
      weights.gemini -= 0.05;
      weights.content -= 0.05;
    }

    // Normalize weights
    const total = Object.values(weights).reduce((a, b) => a + b, 0);
    Object.keys(weights).forEach(key => {
      weights[key] = weights[key] / total;
    });
  };

  adjustWeights(scores);

  // Calculate final score with confidence adjustment
  return Math.round(
    Object.entries(scores).reduce((total, [key, score]) => {
      const confidence = getConfidenceLevel(key, score);
      return total + (score * weights[key] * confidence);
    }, 0)
  );
}

function getConfidenceLevel(source, score) {
  const confidenceLevels = {
    safeBrowsing: 0.95,
    ml: 0.85,
    domain: 0.90,
    gemini: 0.80,
    content: 0.75
  };

  // Adjust confidence based on score extremity
  const baseConfidence = confidenceLevels[source];
  const scoreExtremity = Math.abs(50 - score) / 50; // 0 to 1
  return baseConfidence * (1 + scoreExtremity * 0.2); // Up to 20% boost
}

function generateDetailedMessage(isSafe, scores) {
  if (isSafe) {
    return 'This URL appears to be safe.';
  }

  const highestRisk = Object.entries(scores)
    .sort(([,a], [,b]) => b - a)[0];
    
  return `Warning: This URL may be unsafe! ${getDetailedRiskExplanation(highestRisk)}`;
}

function getDetailedRiskExplanation([source, score]) {
  const explanations = {
    safeBrowsing: 'Known threats detected by Google Safe Browsing.',
    gemini: 'AI analysis detected suspicious patterns.',
    domain: 'Domain analysis revealed suspicious characteristics.',
    ml: 'Machine learning model detected phishing indicators.',
    content: 'Page content contains suspicious elements.'
  };

  return explanations[source] || 'Multiple risk factors detected.';
}

// Add missing score calculation functions
function calculateGeminiScore(geminiResult) {
  if (!geminiResult || !geminiResult.explanation) return 50;
  
  const confidence = geminiResult.explanation.match(/\b(\d+)%?\b/);
  const confidenceScore = confidence ? parseInt(confidence[1]) : 50;
  
  // Calculate risk score inversely proportional to confidence
  return geminiResult.safe ? 0 : (100 - confidenceScore);
}

function generateTechnicalReport(scores, contentAnalysis) {
  return {
    safeBrowsingScore: scores.safeBrowsing,
    aiConfidence: 100 - scores.gemini,
    domainTrustScore: 100 - scores.domain,
    mlDetectionScore: scores.ml,
    contentRiskScore: scores.content,
    indicators: contentAnalysis?.indicators || {}
  };
}

function generateDetailedFlags(safeBrowsing, gemini, domain, contentAnalysis, mlAnalysis) {
  const flags = [];

  // SafeBrowsing flags
  if (!safeBrowsing.safe) {
    flags.push('Detected by Google Safe Browsing API');
  }

  // Gemini AI flags
  if (!gemini.safe) {
    flags.push('AI analysis detected suspicious patterns');
  }

  // Domain flags
  if (domain.age === 'Unknown' || domain.age === '1 week') {
    flags.push('Recently registered or unknown domain age');
  }
  if (!domain.isSecure) {
    flags.push('No SSL certificate');
  }
  if (domain.details?.suspiciousPatterns?.length > 0) {
    flags.push(`Suspicious patterns found: ${domain.details.suspiciousPatterns.join(', ')}`);
  }

  // Content analysis flags
  if (contentAnalysis?.hasPhishingIndicators) {
    if (contentAnalysis.indicators.hasPasswordField) {
      flags.push('Password field on suspicious page');
    }
    if (contentAnalysis.indicators.hasLoginForm) {
      flags.push('Login form with suspicious characteristics');
    }
    if (contentAnalysis.indicators.hasObfuscatedCode) {
      flags.push('Obfuscated code detected');
    }
  }

  // ML analysis flags
  if (mlAnalysis?.score > 70) {
    flags.push('High risk score from machine learning analysis');
  }

  return flags;
}

function checkSuspiciousPatterns(domain) {
  const patterns = [
    {
      pattern: /^[0-9]+/,
      type: 'Numeric prefix',
      weight: 15
    },
    {
      pattern: /[-_.]{2,}/,
      type: 'Multiple separators',
      weight: 10
    },
    {
      pattern: /(login|verify|account|secure|banking|support|security|update|confirm)\.(tk|ml|ga|cf|gq|xyz)$/i,
      type: 'Suspicious TLD combination',
      weight: 25
    },
    {
      pattern: /(?:paypal|apple|google|microsoft|amazon|facebook|instagram|twitter|bitcoin|crypto|wallet).*(?!\.com$)/i,
      type: 'Brand impersonation',
      weight: 30
    },
    {
      pattern: /[0oIl]{3,}/i,
      type: 'Homograph attack characters',
      weight: 20
    },
    {
      pattern: /(secure|login|account|verify|auth|signin|security|update|confirm).{30,}/i,
      type: 'Long suspicious subdomain',
      weight: 15
    }
  ];

  return patterns
    .filter(({ pattern }) => pattern.test(domain))
    .map(({ type, weight }) => ({ type, weight }));
}

function calculateConfidenceScore(scores, safeBrowsingResult, mlAnalysis) {
  // Weight different factors for confidence calculation
  const weights = {
    safeBrowsing: 0.4,
    mlModel: 0.3,
    overallScore: 0.3
  };

  const confidenceFactors = {
    safeBrowsing: safeBrowsingResult.safe ? 100 : 0,
    mlModel: 100 - Math.abs(50 - mlAnalysis.score), // Higher confidence when ML score is decisive
    overallScore: scores.domain > 80 || scores.domain < 20 ? 100 : 60 // Higher confidence for clear cases
  };

  return Math.round(
    Object.entries(weights).reduce((total, [key, weight]) => {
      return total + (confidenceFactors[key] * weight);
    }, 0)
  );
}

async function handlePhishReport(url, details) {
  try {
    // Store report in local storage for persistence
    const reports = await chrome.storage.local.get('phishingReports') || { phishingReports: [] };
    reports.phishingReports.push({
      url,
      details,
      timestamp: new Date().toISOString(),
      status: 'pending'
    });
    await chrome.storage.local.set(reports);

    // Update URL check cache to reflect the report
    const cached = urlCache.get(url);
    if (cached) {
      cached.result.urlDetails.riskScore += 10; // Increase risk score
      cached.result.urlDetails.flags.push('Reported as phishing by users');
      urlCache.set(url, cached);
    }

    return true;
  } catch (error) {
    console.error('Failed to submit phishing report:', error);
    throw new Error('Failed to submit report');
  }
}

// ... rest of your existing helper functions ...
