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
    checkUrl(request.url)
      .then(sendResponse)
      .catch(error => {
        console.error('Error in checkUrl:', error);
        sendResponse({
          safe: false,
          message: error.message || 'Failed to analyze URL',
          safeBrowsingDetails: 'Analysis failed',
          geminiDetails: 'Analysis failed',
          urlDetails: {
            domainAge: 'Unknown',
            ssl: 'Unknown',
            riskScore: 100,
            threatLevel: 'Critical',
            flags: ['Error during analysis']
          }
        });
      });
    return true;
  }
});

async function checkUrl(url) {
  try {
    const urlInfo = new URL(url);
    
    // Enhanced parallel checks
    const [safeBrowsingResult, geminiResult, domainInfo, mlAnalysis, contentAnalysis] = await Promise.all([
      checkSafeBrowsing(url),
      checkGemini(url, urlInfo),
      analyzeDomain(urlInfo),
      checkWithHuggingFace(url),
      analyzeUrlContent(url)
    ]);

    // Weighted scoring system
    const scores = {
      safeBrowsing: safeBrowsingResult.safe ? 0 : 40,
      gemini: calculateGeminiScore(geminiResult),
      domain: calculateDomainScore(domainInfo),
      ml: mlAnalysis.score,
      content: contentAnalysis.score
    };

    const totalScore = calculateWeightedScore(scores);
    const isSafe = totalScore < 60 && safeBrowsingResult.safe && !contentAnalysis.hasPhishingIndicators;

    return {
      safe: isSafe,
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
    const age = '5 years+'; // Simplified for now
    const ssl = urlInfo.protocol === 'https:' ? 'Valid SSL' : 'No SSL';
    
    // Basic domain analysis
    const analysis = {
      age: age,
      ssl: ssl,
      isSecure: urlInfo.protocol === 'https:',
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

function checkSuspiciousPatterns(domain) {
  const patterns = [
    { pattern: /^[0-9]+/, type: 'Numeric prefix' },
    { pattern: /[-_.]{2,}/, type: 'Multiple separators' },
    { pattern: /(login|verify|account|secure|banking)\.(tk|ml|ga|cf|gq)$/, type: 'Suspicious TLD' },
    { pattern: /paypal|apple|google|microsoft|amazon/i, type: 'Brand impersonation' }
  ];

  return patterns
    .filter(({ pattern }) => pattern.test(domain))
    .map(({ type }) => type);
}

function calculateRiskScore(urlInfo, domainInfo) {
  let score = 0;
  
  // Domain age scoring
  const ageScores = {
    '1 week': 50,
    '1 month': 40,
    '6 months': 20,
    '1 year': 10,
    '5 years+': 0,
    'Unknown': 35
  };
  score += ageScores[domainInfo.age] || 35;

  // SSL scoring
  if (!domainInfo.isSecure) score += 30;

  // Suspicious patterns scoring
  if (domainInfo.details.suspiciousPatterns) {
    score += domainInfo.details.suspiciousPatterns.length * 15;
  }

  // Special characters and numbers
  if (domainInfo.details.hasNumbers) score += 10;
  score += domainInfo.details.specialChars * 5;

  // Excessive length
  if (domainInfo.details.length > 30) score += 10;

  // Too many subdomains
  if (domainInfo.details.subdomains > 3) score += 15;

  return Math.min(Math.round(score), 100);
}

async function checkWithHuggingFace(url) {
  try {
    const response = await fetch('https://api-inference.huggingface.co/models/deepset/phishing_url_detector', {
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
      hasPasswordField: /<input[^>]*type=["']password["'][^>]*>/i.test(text),
      hasLoginForm: /<form[^>]*>[\s\S]*?(?:login|signin|password)[\s\S]*?<\/form>/i.test(text),
      hasSuspiciousRedirects: /window\.location|document\.location|setTimeout/i.test(text),
      hasObfuscatedCode: /(eval|unescape|escape|atob|btoa)\s*\(/i.test(text),
      hasDataExfiltration: /XMLHttpRequest|fetch\s*\(|navigator\.sendBeacon/i.test(text)
    };

    const score = Object.values(indicators).filter(Boolean).length * 20;
    
    return {
      score: Math.min(score, 100),
      hasPhishingIndicators: score > 40,
      indicators
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

function calculateWeightedScore(scores) {
  const weights = {
    safeBrowsing: 0.3,
    gemini: 0.2,
    domain: 0.2,
    ml: 0.2,
    content: 0.1
  };

  return Math.round(
    Object.entries(scores).reduce((total, [key, score]) => {
      return total + (score * weights[key]);
    }, 0)
  );
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

function calculateDomainScore(domainInfo) {
  let score = 0;
  
  // Domain age risk
  const ageScores = {
    '1 week': 50,
    '1 month': 40,
    '6 months': 20,
    '1 year': 10,
    '5 years+': 0,
    'Unknown': 35
  };
  score += ageScores[domainInfo.age] || 35;

  // SSL check
  if (!domainInfo.isSecure) score += 30;

  // Domain analysis
  if (domainInfo.details) {
    // Suspicious patterns
    if (domainInfo.details.suspiciousPatterns) {
      score += domainInfo.details.suspiciousPatterns.length * 15;
    }
    // Numbers in domain
    if (domainInfo.details.hasNumbers) score += 10;
    // Special characters
    score += (domainInfo.details.specialChars || 0) * 5;
    // Length penalty
    if (domainInfo.details.length > 30) score += 10;
    // Subdomain count
    if (domainInfo.details.subdomains > 3) score += 15;
  }

  return Math.min(score, 100);
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

// ... rest of your existing helper functions ...
