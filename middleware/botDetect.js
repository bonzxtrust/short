const { UAParser } = require('ua-parser-js');

/**
 * Bot Detection Engine
 * Scores each request 0-100 (higher = more likely bot)
 * Uses multiple signals: UA analysis, behavioral patterns, IP reputation
 */

// Known bot UA patterns
const BOT_PATTERNS = [
  /bot|crawler|spider|scraper|curl|wget|python|java|go-http|axios|fetch|node-fetch/i,
  /googlebot|bingbot|yandexbot|duckduckbot|baiduspider|facebookexternalhit/i,
  /semrushbot|ahrefsbot|mj12bot|dotbot|rogerbot|exabot/i,
  /headless|phantomjs|selenium|webdriver|puppeteer|playwright/i,
  /zgrab|masscan|nmap|nikto|sqlmap/i,
];

// Suspicious UA patterns (not definitive bots but suspicious)
const SUSPICIOUS_PATTERNS = [
  /^mozilla\/5\.0 \(compatible\)$/i,  // Too generic
  /^$/,                                 // Empty UA
];

// Known datacenter/VPN IP ranges (simplified - in production use a proper DB)
const DATACENTER_ASNS = ['AS14061', 'AS16509', 'AS15169', 'AS8075', 'AS13335'];

function detectBot(req) {
  const ua = req.headers['user-agent'] || '';
  const parser = new UAParser(ua);
  const result = parser.getResult();

  let score = 0;
  const reasons = [];
  const signals = {};

  // === UA ANALYSIS ===
  // Check known bot patterns
  for (const pattern of BOT_PATTERNS) {
    if (pattern.test(ua)) {
      score += 80;
      reasons.push('Known bot user-agent');
      signals.knownBot = true;
      break;
    }
  }

  // Check suspicious patterns
  for (const pattern of SUSPICIOUS_PATTERNS) {
    if (pattern.test(ua)) {
      score += 40;
      reasons.push('Suspicious user-agent pattern');
      signals.suspiciousUA = true;
      break;
    }
  }

  // No browser detected
  if (!result.browser.name && !signals.knownBot) {
    score += 30;
    reasons.push('No browser detected in UA');
    signals.noBrowser = true;
  }

  // No OS detected
  if (!result.os.name && !signals.knownBot) {
    score += 20;
    reasons.push('No OS detected in UA');
    signals.noOS = true;
  }

  // === HEADER ANALYSIS ===
  const acceptLang = req.headers['accept-language'];
  const acceptEnc = req.headers['accept-encoding'];
  const accept = req.headers['accept'];

  if (!acceptLang) {
    score += 15;
    reasons.push('Missing Accept-Language header');
    signals.noAcceptLang = true;
  }

  if (!acceptEnc) {
    score += 10;
    reasons.push('Missing Accept-Encoding header');
    signals.noAcceptEnc = true;
  }

  if (!accept) {
    score += 10;
    reasons.push('Missing Accept header');
    signals.noAccept = true;
  }

  // === REFERER ANALYSIS ===
  const referer = req.headers['referer'] || req.headers['referrer'] || '';
  signals.referer = referer;

  // Direct access with no referer is normal, but combined with other signals is suspicious
  if (!referer && score > 20) {
    score += 5;
    reasons.push('No referer with other suspicious signals');
  }

  // === TIMING ANALYSIS ===
  // Check if request came too fast (< 100ms from page load - impossible for human)
  const requestTime = req.headers['x-request-time'];
  if (requestTime && parseInt(requestTime) < 100) {
    score += 25;
    reasons.push('Request too fast (< 100ms)');
    signals.tooFast = true;
  }

  // === CLIENT-SIDE SIGNALS (from frontend) ===
  const clientSignals = req.headers['x-client-signals'];
  if (clientSignals) {
    try {
      const cs = JSON.parse(Buffer.from(clientSignals, 'base64').toString());
      signals.client = cs;

      if (!cs.mouseEvents) { score += 20; reasons.push('No mouse events detected'); }
      if (!cs.keyboardEvents) { score += 10; reasons.push('No keyboard events detected'); }
      if (!cs.touchEvents && result.device.type === 'mobile') { score += 15; reasons.push('Mobile device but no touch events'); }
      if (cs.webdriver) { score += 90; reasons.push('WebDriver detected'); }
      if (!cs.cookiesEnabled) { score += 15; reasons.push('Cookies disabled'); }
      if (!cs.localStorageEnabled) { score += 15; reasons.push('LocalStorage disabled'); }
      if (cs.screenWidth === 0 || cs.screenHeight === 0) { score += 30; reasons.push('Zero screen dimensions'); }
      if (!cs.timezone) { score += 10; reasons.push('No timezone detected'); }
      if (cs.plugins === 0 && result.browser.name !== 'Firefox') { score += 10; reasons.push('No browser plugins'); }
    } catch (e) {
      // Invalid client signals
      score += 5;
    }
  } else {
    // No client signals at all (direct API call)
    score += 10;
    reasons.push('No client-side signals provided');
  }

  // Cap score at 100
  score = Math.min(100, score);

  const isBot = score >= 50;
  const humanScore = Math.max(0, 100 - score);

  return {
    isBot,
    score,
    humanScore,
    reasons,
    signals,
    browser: result.browser.name || 'Unknown',
    browserVersion: result.browser.version || '',
    os: result.os.name || 'Unknown',
    osVersion: result.os.version || '',
    device: result.device.type || 'desktop',
    deviceModel: result.device.model || '',
    botReason: reasons.join('; ') || null,
  };
}

module.exports = { detectBot };
