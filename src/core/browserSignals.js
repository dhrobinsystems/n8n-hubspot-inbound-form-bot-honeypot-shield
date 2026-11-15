/**
 * Browser header, Origin/Referer and UTM integrity checks.
 *
 * These checks assume the visitor's browser posts directly to the shield
 * (Express endpoint or n8n webhook). If another server relays the submission,
 * forward the original headers or expect higher browser-signal scores.
 */

const AUTOMATION_UA_RE =
  /\b(?:curl|wget|python-requests|python-urllib|aiohttp|httpx|go-http-client|java\/\d|okhttp|axios|node-fetch|undici|libwww-perl|scrapy|httpclient|postmanruntime|insomnia|headlesschrome|phantomjs|selenium|webdriver|puppeteer|playwright|slimerjs|crawler|spider|bot)\b/i;
export const UTM_KEYS = ['utm_source', 'utm_medium', 'utm_campaign', 'utm_term', 'utm_content'];
const UTM_ALLOWED_RE = /^[\p{L}\p{N} _.,:|+\-/()%@&=!#~]*$/u;
const INJECTION_RE = /<|>|javascript:|data:text|\{\{|\$\{|--\s|;\s*drop\s|union\s+select|\bon\w+\s*=/i;

function lowerHeaders(headers) {
  return Object.fromEntries(Object.entries(headers || {}).map(([k, v]) => [k.toLowerCase(), Array.isArray(v) ? v[0] : v]));
}

export function originOf(url) {
  try {
    const u = new URL(String(url));
    return `${u.protocol}//${u.host}`.toLowerCase();
  } catch {
    return null;
  }
}

function browserFamily(ua) {
  const edge = ua.match(/Edg\/(\d+)/);
  if (edge) return { family: 'edge', major: Number(edge[1]) };
  const chrome = ua.match(/(?:Chrome|CriOS)\/(\d+)/);
  if (chrome) return { family: 'chrome', major: Number(chrome[1]) };
  const firefox = ua.match(/(?:Firefox|FxiOS)\/(\d+)/);
  if (firefox) return { family: 'firefox', major: Number(firefox[1]) };
  const safari = ua.match(/Version\/(\d+)(?:\.\d+)?.*Safari\//);
  if (safari) return { family: 'safari', major: Number(safari[1]) };
  return { family: 'unknown', major: 0 };
}

export function evaluateBrowserSignals(headers, browserConfig) {
  const h = lowerHeaders(headers);
  const signals = [];
  const ua = String(h['user-agent'] || '').trim();
  if (!ua) {
    signals.push({ id: 'ua_missing', points: 40, detail: 'no User-Agent header' });
  } else {
    if (AUTOMATION_UA_RE.test(ua)) signals.push({ id: 'ua_automation', points: 70, detail: 'User-Agent of an HTTP library, headless browser or crawler' });
    else if (ua.length < 20) signals.push({ id: 'ua_too_short', points: 15, detail: `${ua.length}-character User-Agent` });
    const { family, major } = browserFamily(ua);
    const hasFetchMetadata = Boolean(h['sec-fetch-mode'] || h['sec-fetch-site'] || h['sec-fetch-dest']);
    const expectsFetchMetadata =
      ((family === 'chrome' || family === 'edge') && major >= 80) || (family === 'firefox' && major >= 90);
    if (expectsFetchMetadata && !hasFetchMetadata) {
      signals.push({ id: 'fetch_metadata_missing', points: 20, detail: `${family} ${major} normally sends Sec-Fetch-* headers` });
    }
    if ((family === 'chrome' || family === 'edge') && major >= 90 && hasFetchMetadata && !h['sec-ch-ua']) {
      signals.push({ id: 'client_hints_missing', points: 10, detail: 'Chromium without Sec-CH-UA client hints' });
    }
  }
  if (!h['accept-language']) signals.push({ id: 'accept_language_missing', points: 15, detail: 'no Accept-Language header' });
  if (browserConfig.allowedOrigins.length) {
    const origin = h.origin ? String(h.origin).replace(/\/+$/, '').toLowerCase() : null;
    const refererOrigin = h.referer ? originOf(h.referer) : null;
    const presented = origin && origin !== 'null' ? origin : refererOrigin;
    if (!presented) signals.push({ id: 'origin_missing', points: 20, detail: 'neither Origin nor Referer present' });
    else if (!browserConfig.allowedOrigins.includes(presented)) {
      signals.push({ id: 'origin_not_allowed', points: 50, detail: `origin ${presented} is not in ALLOWED_ORIGINS` });
    }
  }
  return { signals };
}

export function utmFromPageUri(pageUri) {
  try {
    const params = new URL(String(pageUri)).searchParams;
    return Object.fromEntries(UTM_KEYS.filter((k) => params.has(k)).map((k) => [k, params.get(k)]));
  } catch {
    return {};
  }
}

export function evaluateUtmSignals({ utm = {}, pageUri = '', browserConfig }) {
  const signals = [];
  const fromPage = pageUri ? utmFromPageUri(pageUri) : {};
  const merged = { ...fromPage, ...utm };
  const present = UTM_KEYS.filter((k) => merged[k] !== undefined && String(merged[k]).trim() !== '');
  let overlong = false;
  let invalid = false;
  let injection = false;
  for (const key of present) {
    const value = String(merged[key]);
    if (value.length > 200) overlong = true;
    if (INJECTION_RE.test(value)) injection = true;
    else if (!UTM_ALLOWED_RE.test(value)) invalid = true;
  }
  if (injection) signals.push({ id: 'utm_injection', points: 35, detail: 'markup, script or query syntax inside UTM values' });
  if (invalid) signals.push({ id: 'utm_invalid_chars', points: 15, detail: 'unexpected characters in UTM values' });
  if (overlong) signals.push({ id: 'utm_overlong', points: 10, detail: 'UTM value longer than 200 characters' });
  if (present.length && !present.includes('utm_source')) {
    signals.push({ id: 'utm_incomplete', points: 10, detail: 'utm_medium/utm_campaign without utm_source' });
  }
  const mismatched = UTM_KEYS.filter((k) => fromPage[k] !== undefined && utm[k] !== undefined && String(fromPage[k]) !== String(utm[k]));
  if (mismatched.length) signals.push({ id: 'utm_mismatch', points: 10, detail: `form UTM differs from page URL UTM (${mismatched.join(', ')})` });
  if (browserConfig.requireUtm && !present.length) signals.push({ id: 'utm_missing', points: 10, detail: 'REQUIRE_UTM=true and no UTM parameters' });
  if (pageUri) {
    const pageOrigin = originOf(pageUri);
    if (!pageOrigin) signals.push({ id: 'page_uri_invalid', points: 10, detail: 'pageUri is not a valid URL' });
    else if (browserConfig.allowedOrigins.length && !browserConfig.allowedOrigins.includes(pageOrigin)) {
      signals.push({ id: 'page_uri_foreign', points: 20, detail: `pageUri origin ${pageOrigin} is not in ALLOWED_ORIGINS` });
    }
  }
  return { signals, utm: Object.fromEntries(present.map((k) => [k, String(merged[k]).slice(0, 200)])) };
}
