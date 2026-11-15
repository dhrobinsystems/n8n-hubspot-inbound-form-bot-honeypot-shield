/**
 * Configuration loader shared by the Express middleware and the n8n workflow.
 *
 * Fail-safe rules:
 * - DRY_RUN and SANDBOX_MODE stay true unless explicitly set to false/0/no/off.
 * - Placeholder values ("your_..._here") are treated as "not configured".
 * - ASN lookups default to "none" (no outbound calls) and HubSpot delivery is
 *   impossible while the portal ID, form GUID or token are placeholders.
 *
 * This file is embedded verbatim into the n8n Code nodes by
 * scripts/build-n8n-workflow.js: keep top-level names unique across src/core/.
 */

const SHIELD_PLACEHOLDER_RE = /^(?:|your_[a-z0-9_]*_here|changeme|change_me|placeholder|x{3,})$/i;

export function isPlaceholderValue(value) {
  if (value === undefined || value === null) return true;
  return SHIELD_PLACEHOLDER_RE.test(String(value).trim());
}

/** true/1/yes/on -> true, false/0/no/off -> false, anything else -> the default. */
export function parseFlag(value, defaultValue) {
  if (value === undefined || value === null) return defaultValue;
  const v = String(value).trim().toLowerCase();
  if (['true', '1', 'yes', 'on'].includes(v)) return true;
  if (['false', '0', 'no', 'off'].includes(v)) return false;
  return defaultValue;
}

function parsePositiveInt(value, fallback) {
  const n = Number.parseInt(String(value ?? ''), 10);
  return Number.isFinite(n) && n >= 0 ? n : fallback;
}

function parseList(value, fallback = []) {
  if (value === undefined || value === null || String(value).trim() === '') return fallback;
  return String(value)
    .split(',')
    .map((item) => item.trim())
    .filter(Boolean);
}

export function loadShieldConfig(env = {}) {
  const read = (key, fallback = '') => {
    const value = env[key];
    return value === undefined || value === null ? fallback : String(value).trim();
  };
  return {
    dryRun: parseFlag(env.DRY_RUN, true),
    sandboxMode: parseFlag(env.SANDBOX_MODE, true),
    silentReject: parseFlag(env.SILENT_REJECT, true),
    thresholds: {
      quarantine: parsePositiveInt(env.QUARANTINE_SCORE_THRESHOLD, 40),
      block: parsePositiveInt(env.BLOCK_SCORE_THRESHOLD, 80),
    },
    honeypot: {
      fieldNames: parseList(env.HONEYPOT_FIELDS, ['website_url', 'fax_number']),
      timestampField: read('FORM_TIMESTAMP_FIELD', '_rendered_at'),
      tokenField: read('FORM_TOKEN_FIELD', '_render_token'),
      tokenSecret: read('FORM_TOKEN_SECRET'),
      minFillSeconds: parsePositiveInt(env.MIN_FILL_SECONDS, 3),
      maxFormAgeSeconds: parsePositiveInt(env.MAX_FORM_AGE_SECONDS, 7200),
    },
    velocity: {
      windowSeconds: parsePositiveInt(env.VELOCITY_WINDOW_SECONDS, 600),
      maxPerIp: parsePositiveInt(env.VELOCITY_MAX_PER_IP, 5),
      maxPerEmailDomain: parsePositiveInt(env.VELOCITY_MAX_PER_EMAIL_DOMAIN, 15),
      maxPerFreeMailDomain: parsePositiveInt(env.VELOCITY_MAX_PER_FREEMAIL_DOMAIN, 200),
      maxPerEmail: parsePositiveInt(env.VELOCITY_MAX_PER_EMAIL, 3),
    },
    email: {
      disposableAction: read('DISPOSABLE_EMAIL_ACTION', 'block').toLowerCase() === 'quarantine' ? 'quarantine' : 'block',
      extraDisposableDomains: parseList(env.DISPOSABLE_DOMAINS_EXTRA).map((d) => d.toLowerCase()),
      allowlistDomains: parseList(env.ALLOWLIST_EMAIL_DOMAINS).map((d) => d.toLowerCase()),
    },
    text: {
      fieldsToScore: parseList(env.TEXT_FIELDS_TO_SCORE, ['firstname', 'lastname', 'company', 'message']),
      maxUrlsInMessage: parsePositiveInt(env.MAX_URLS_IN_MESSAGE, 2),
    },
    ip: {
      asnProvider: ['none', 'header', 'ipinfo'].includes(read('ASN_LOOKUP_PROVIDER', 'none').toLowerCase())
        ? read('ASN_LOOKUP_PROVIDER', 'none').toLowerCase()
        : 'none',
      asnHeader: read('ASN_HEADER', 'x-client-asn').toLowerCase(),
      asnOrgHeader: read('ASN_ORG_HEADER', 'x-client-asn-org').toLowerCase(),
      ipinfoToken: read('IPINFO_TOKEN'),
      ipinfoTimeoutMs: parsePositiveInt(env.IPINFO_TIMEOUT_MS, 1500),
      extraDatacenterAsns: parseList(env.DATACENTER_ASNS_EXTRA).map((a) => Number.parseInt(a.replace(/^AS/i, ''), 10)).filter(Number.isFinite),
      blocklistCidrs: parseList(env.IP_BLOCKLIST_CIDRS),
      allowlistCidrs: parseList(env.IP_ALLOWLIST_CIDRS),
      clientIpHeader: read('CLIENT_IP_HEADER', 'x-forwarded-for').toLowerCase(),
    },
    browser: {
      allowedOrigins: parseList(env.ALLOWED_ORIGINS).map((o) => o.replace(/\/+$/, '').toLowerCase()),
      requireUtm: parseFlag(env.REQUIRE_UTM, false),
    },
    hubspot: {
      portalId: read('HUBSPOT_PORTAL_ID'),
      sandboxPortalId: read('HUBSPOT_SANDBOX_PORTAL_ID'),
      formGuid: read('HUBSPOT_FORM_GUID'),
      allowedFormGuids: parseList(env.HUBSPOT_ALLOWED_FORM_GUIDS),
      token: read('HUBSPOT_PRIVATE_APP_TOKEN'),
      formsBaseUrl: read('HUBSPOT_FORMS_BASE_URL', 'https://api.hsforms.com'),
      forwardFields: parseList(env.FORWARD_FIELDS, ['email', 'firstname', 'lastname', 'company', 'phone', 'jobtitle', 'message', 'website']),
      timeoutMs: parsePositiveInt(env.HUBSPOT_TIMEOUT_MS, 8000),
    },
    quarantine: {
      webhookUrl: read('QUARANTINE_WEBHOOK_URL'),
      storeRawIp: parseFlag(env.QUARANTINE_STORE_RAW_IP, false),
      hashSalt: read('QUARANTINE_HASH_SALT'),
    },
  };
}

/** Errors stop processing; warnings are reported in responses and logs. */
export function validateShieldConfig(config) {
  const errors = [];
  const warnings = [];
  const live = !config.dryRun;
  if (config.thresholds.quarantine >= config.thresholds.block) {
    errors.push('QUARANTINE_SCORE_THRESHOLD must be lower than BLOCK_SCORE_THRESHOLD');
  }
  if (config.thresholds.block > 100) errors.push('BLOCK_SCORE_THRESHOLD must be 100 or lower');
  if (!config.honeypot.fieldNames.length) warnings.push('No HONEYPOT_FIELDS configured');
  if (isPlaceholderValue(config.honeypot.tokenSecret)) {
    warnings.push('FORM_TOKEN_SECRET is not set: render timestamps are accepted unsigned');
  }
  if (isPlaceholderValue(config.quarantine.hashSalt)) {
    if (live) errors.push('QUARANTINE_HASH_SALT is required when DRY_RUN=false');
    else warnings.push('QUARANTINE_HASH_SALT is a placeholder (acceptable in dry run only)');
  }
  if (config.ip.asnProvider === 'ipinfo' && isPlaceholderValue(config.ip.ipinfoToken)) {
    errors.push('ASN_LOOKUP_PROVIDER=ipinfo requires IPINFO_TOKEN');
  }
  if (live) {
    if (isPlaceholderValue(config.hubspot.portalId)) errors.push('HUBSPOT_PORTAL_ID is missing or a placeholder');
    if (isPlaceholderValue(config.hubspot.formGuid) && !config.hubspot.allowedFormGuids.length) {
      errors.push('HUBSPOT_FORM_GUID (or HUBSPOT_ALLOWED_FORM_GUIDS) is required when DRY_RUN=false');
    }
    if (config.sandboxMode && isPlaceholderValue(config.hubspot.sandboxPortalId)) {
      errors.push('SANDBOX_MODE=true with DRY_RUN=false requires HUBSPOT_SANDBOX_PORTAL_ID');
    }
    if (!config.browser.allowedOrigins.length) warnings.push('ALLOWED_ORIGINS is empty: Origin checks are disabled');
  }
  if (!config.sandboxMode && live) warnings.push('SANDBOX_MODE=false and DRY_RUN=false: submissions reach the production portal');
  return { errors, warnings };
}
