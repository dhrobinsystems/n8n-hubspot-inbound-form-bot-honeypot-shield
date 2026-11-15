/**
 * Shield pipeline shared by the Express middleware and the n8n workflow.
 *
 *   evaluateStage   normalize -> honeypot/timing -> email -> velocity -> text -> IP/ASN -> browser/UTM -> verdict
 *   hubspotStage    verdict "allow": forward to the HubSpot Forms API (dry-run / sandbox interlocks);
 *                   a failed delivery falls back to quarantine so no lead is lost
 *   quarantineStage verdict "quarantine" | "block": build a privacy-minimised review record and
 *                   (optionally) POST it to QUARANTINE_WEBHOOK_URL
 *   clientResponse  what the browser sees (identical for accepted and silently rejected submissions)
 *
 * Every stage takes and returns a JSON-serializable context, which is what lets n8n
 * Code nodes run the same functions between Webhook, IF and Respond nodes.
 */
import crypto from 'node:crypto';
import { isPlaceholderValue, validateShieldConfig } from './config.js';
import {
  canonicalMailbox,
  emailDomainOf,
  isFreeMailDomain,
  isValidEmailSyntax,
  matchDisposableDomain,
  normalizeEmailAddress,
} from './disposableDomains.js';
import { analyzeTextField } from './textHeuristics.js';
import { evaluateIpSignals, firstForwardedIp, lookupAsn } from './ipReputation.js';
import { evaluateBrowserSignals, evaluateUtmSignals, UTM_KEYS } from './browserSignals.js';

export const SIGNAL_CATEGORIES = {
  honeypot: 'honeypot',
  timing: 'honeypot',
  email: 'email',
  velocity: 'velocity',
  text: 'text',
  ip: 'ip',
  browser: 'browser',
  utm: 'utm',
  form: 'form',
};
const RESERVED_KEYS = new Set(['hutk', 'pageUri', 'pageName', 'formGuid', 'legalConsentOptions', 'fields', 'context', ...UTM_KEYS]);
const NAME_FIELDS = new Set(['firstname', 'lastname', 'fullname', 'name']);
const MAX_FIELD_VALUE = 10000;

export class ShieldSafetyError extends Error {
  constructor(code, message) {
    super(message || code);
    this.name = 'ShieldSafetyError';
    this.code = code;
  }
}

function lowerKeyed(obj) {
  return Object.fromEntries(Object.entries(obj || {}).map(([k, v]) => [k.toLowerCase(), Array.isArray(v) ? v[0] : v]));
}

function cleanValue(value, max = MAX_FIELD_VALUE) {
  if (value === undefined || value === null) return '';
  if (typeof value === 'object') return '';
  return String(value).replace(/[\u0000-\u0008\u000B\u000C\u000E-\u001F\u007F]/g, '').trim().slice(0, max);
}

export function hashIdentifier(value, salt) {
  if (!value) return null;
  return crypto.createHash('sha256').update(`${salt || 'unsalted'}:${value}`).digest('hex').slice(0, 24);
}

export function issueRenderToken(secret, renderedAtMs = Date.now()) {
  const renderedAt = String(Math.floor(renderedAtMs));
  return { renderedAt, token: crypto.createHmac('sha256', String(secret)).update(`render:${renderedAt}`).digest('hex') };
}

function verifyRenderToken(secret, renderedAt, token) {
  if (!token || !/^[0-9a-f]{64}$/i.test(String(token))) return false;
  const expected = crypto.createHmac('sha256', String(secret)).update(`render:${renderedAt}`).digest('hex');
  return crypto.timingSafeEqual(Buffer.from(expected, 'hex'), Buffer.from(String(token).toLowerCase(), 'hex'));
}

/** Accepts flat form posts (JSON or urlencoded) and HubSpot-style { fields: [{ name, value }], context }. */
export function normalizeSubmission({ body = {}, headers = {}, socketIp = '', query = {} }, config) {
  const flat = {};
  const source = body && typeof body === 'object' && !Array.isArray(body) ? body : {};
  if (Array.isArray(source.fields)) {
    for (const f of source.fields) if (f && typeof f.name === 'string') flat[f.name] = f.value;
  }
  for (const [k, v] of Object.entries(source)) if (k !== 'fields' && k !== 'context') flat[k] = v;
  const context = source.context && typeof source.context === 'object' ? source.context : {};
  const h = lowerKeyed(headers);
  const headerIp = config.ip.clientIpHeader && config.ip.clientIpHeader !== 'none' ? firstForwardedIp(h[config.ip.clientIpHeader]) : '';
  const ip = headerIp || firstForwardedIp(socketIp);
  const honeypotValues = Object.fromEntries(config.honeypot.fieldNames.map((name) => [name, cleanValue(flat[name], 500)]));
  const reserved = new Set([...RESERVED_KEYS, ...config.honeypot.fieldNames, config.honeypot.timestampField, config.honeypot.tokenField]);
  const fields = {};
  for (const [k, v] of Object.entries(flat)) {
    if (reserved.has(k) || !/^[A-Za-z][A-Za-z0-9_]{0,99}$/.test(k)) continue;
    const value = cleanValue(v);
    if (value) fields[k.toLowerCase()] = value;
  }
  const utm = {};
  for (const key of UTM_KEYS) {
    const value = flat[key] ?? query[key];
    if (value !== undefined && value !== null && String(value) !== '') utm[key] = cleanValue(value, 500);
  }
  return {
    email: normalizeEmailAddress(fields.email || ''),
    fields,
    honeypotValues,
    renderedAt: cleanValue(flat[config.honeypot.timestampField], 20),
    renderToken: cleanValue(flat[config.honeypot.tokenField], 100),
    utm,
    hutk: cleanValue(flat.hutk || context.hutk, 100),
    pageUri: cleanValue(flat.pageUri || context.pageUri, 2000),
    pageName: cleanValue(flat.pageName || context.pageName, 300),
    formGuid: cleanValue(flat.formGuid || query.formGuid, 64),
    legalConsentOptions:
      source.legalConsentOptions && typeof source.legalConsentOptions === 'object' ? source.legalConsentOptions : null,
    ip,
    headers: {
      'user-agent': cleanValue(h['user-agent'], 500),
      'accept-language': cleanValue(h['accept-language'], 200),
      origin: cleanValue(h.origin, 300),
      referer: cleanValue(h.referer, 2000),
      'sec-fetch-site': cleanValue(h['sec-fetch-site'], 50),
      'sec-fetch-mode': cleanValue(h['sec-fetch-mode'], 50),
      'sec-fetch-dest': cleanValue(h['sec-fetch-dest'], 50),
      'sec-ch-ua': cleanValue(h['sec-ch-ua'], 300),
      [config.ip.asnHeader]: cleanValue(h[config.ip.asnHeader], 40),
      [config.ip.asnOrgHeader]: cleanValue(h[config.ip.asnOrgHeader], 120),
    },
  };
}

function tag(category, signals) {
  return signals.map((s) => ({ category, ...s }));
}

export function resolveFormGuid(submission, config) {
  const requested = submission.formGuid;
  const allowed = config.hubspot.allowedFormGuids;
  if (requested) {
    if (allowed.includes(requested) || requested === config.hubspot.formGuid) return { formGuid: requested, allowed: true };
    return { formGuid: requested, allowed: false };
  }
  return { formGuid: isPlaceholderValue(config.hubspot.formGuid) ? null : config.hubspot.formGuid, allowed: true };
}

export function decideVerdict(signals, thresholds) {
  const score = Math.min(100, signals.reduce((sum, s) => sum + (s.points || 0), 0));
  const hardBlock = signals.filter((s) => s.hard === 'block').map((s) => s.id);
  const hardQuarantine = signals.filter((s) => s.hard === 'quarantine').map((s) => s.id);
  let verdict = 'allow';
  let reason = 'score_below_threshold';
  if (hardBlock.length) {
    verdict = 'block';
    reason = `hard_rule:${hardBlock[0]}`;
  } else if (score >= thresholds.block) {
    verdict = 'block';
    reason = 'score_at_or_above_block_threshold';
  } else if (hardQuarantine.length) {
    verdict = 'quarantine';
    reason = `hard_rule:${hardQuarantine[0]}`;
  } else if (score >= thresholds.quarantine) {
    verdict = 'quarantine';
    reason = 'score_at_or_above_quarantine_threshold';
  }
  return { verdict, reason, score };
}

export async function evaluateStage(input, { config, velocityTracker, fetchImpl, now = Date.now() }) {
  const receivedAt = new Date(now).toISOString();
  const { errors, warnings } = validateShieldConfig(config);
  if (errors.length) {
    return { status: 'error', reason: 'config_invalid', errors, warnings, receivedAt, dryRun: config.dryRun, sandboxMode: config.sandboxMode };
  }
  const submission = normalizeSubmission(input, config);
  const signals = [];

  // 1. Honeypot fields and render timing
  const filledTraps = Object.entries(submission.honeypotValues).filter(([, v]) => v !== '').map(([k]) => k);
  if (filledTraps.length) {
    signals.push({ category: 'honeypot', id: 'honeypot_filled', points: 100, hard: 'block', detail: `hidden field(s) filled: ${filledTraps.join(', ')}` });
  }
  const renderedAtMs = /^\d{10,13}$/.test(submission.renderedAt)
    ? submission.renderedAt.length === 13
      ? Number(submission.renderedAt)
      : Number(submission.renderedAt) * 1000
    : null;
  if (renderedAtMs === null) {
    signals.push({ category: 'timing', id: 'render_timestamp_missing', points: 15, detail: `no ${config.honeypot.timestampField} value` });
  } else {
    const elapsed = (now - renderedAtMs) / 1000;
    if (elapsed < 0) signals.push({ category: 'timing', id: 'render_timestamp_future', points: 30, detail: 'render time is in the future' });
    else if (elapsed < config.honeypot.minFillSeconds) {
      signals.push({ category: 'timing', id: 'filled_too_fast', points: 45, detail: `submitted ${elapsed.toFixed(1)}s after render` });
    } else if (elapsed > config.honeypot.maxFormAgeSeconds) {
      signals.push({ category: 'timing', id: 'form_stale', points: 15, detail: `form rendered ${Math.round(elapsed)}s ago` });
    }
    if (!isPlaceholderValue(config.honeypot.tokenSecret)) {
      if (!verifyRenderToken(config.honeypot.tokenSecret, submission.renderedAt, submission.renderToken)) {
        signals.push({ category: 'timing', id: 'render_token_invalid', points: 40, detail: 'render token missing or not signed by FORM_TOKEN_SECRET' });
      }
    }
  }

  // 2. Form GUID allowlist
  const form = resolveFormGuid(submission, config);
  if (!form.allowed) signals.push({ category: 'form', id: 'form_guid_not_allowed', points: 100, hard: 'block', detail: 'formGuid not in HUBSPOT_ALLOWED_FORM_GUIDS' });

  // 3. Email syntax, disposable providers
  const domain = emailDomainOf(submission.email);
  const emailAllowlisted = domain && config.email.allowlistDomains.includes(domain);
  if (!submission.email) {
    signals.push({ category: 'email', id: 'email_missing', points: 100, hard: 'block', detail: 'no email field' });
  } else if (!isValidEmailSyntax(submission.email)) {
    signals.push({ category: 'email', id: 'email_invalid', points: 100, hard: 'block', detail: 'email fails syntax check' });
  } else if (!emailAllowlisted) {
    const disposable = matchDisposableDomain(domain, config.email.extraDisposableDomains);
    if (disposable) {
      signals.push({
        category: 'email',
        id: 'email_disposable',
        points: 60,
        hard: config.email.disposableAction,
        detail: `disposable provider ${disposable}`,
      });
    }
  }

  // 4. IP + ASN (needed before velocity for the allowlist decision)
  const asnInfo = await lookupAsn({ ip: submission.ip, headers: submission.headers, ipConfig: config.ip, fetchImpl });
  const ipResult = evaluateIpSignals({ ip: submission.ip, asnInfo, ipConfig: config.ip });
  signals.push(...tag('ip', ipResult.signals));

  // 5. Velocity per IP, email domain and canonical mailbox
  const velocity = {};
  if (velocityTracker) {
    const keys = [];
    if (submission.ip && !ipResult.allowlisted) keys.push(`ip:${submission.ip}`);
    if (domain && !emailAllowlisted) keys.push(`domain:${domain}`);
    if (submission.email) keys.push(`mailbox:${canonicalMailbox(submission.email)}`);
    const counts = velocityTracker.hit(keys, now);
    Object.assign(velocity, counts);
    const ipCount = counts[`ip:${submission.ip}`] || 0;
    const domainCount = counts[`domain:${domain}`] || 0;
    const mailboxCount = counts[`mailbox:${canonicalMailbox(submission.email)}`] || 0;
    const domainLimit = isFreeMailDomain(domain) ? config.velocity.maxPerFreeMailDomain : config.velocity.maxPerEmailDomain;
    if (config.velocity.maxPerIp && ipCount > config.velocity.maxPerIp) {
      signals.push({ category: 'velocity', id: 'velocity_ip_exceeded', points: 100, hard: 'block', detail: `${ipCount} submissions from this IP in ${config.velocity.windowSeconds}s` });
    }
    if (domainLimit && domainCount > domainLimit) {
      signals.push({ category: 'velocity', id: 'velocity_domain_exceeded', points: 50, hard: 'quarantine', detail: `${domainCount} submissions from @${domain} in ${config.velocity.windowSeconds}s` });
    }
    if (config.velocity.maxPerEmail && mailboxCount > config.velocity.maxPerEmail) {
      signals.push({ category: 'velocity', id: 'velocity_mailbox_exceeded', points: 30, hard: 'quarantine', detail: `${mailboxCount} submissions for one mailbox in ${config.velocity.windowSeconds}s` });
    }
  }

  // 6. Gibberish / entropy / spam heuristics on free text
  const textScores = {};
  for (const name of config.text.fieldsToScore) {
    const value = submission.fields[name];
    if (!value) continue;
    const kind = NAME_FIELDS.has(name) ? 'name' : name === 'message' || name === 'comments' ? 'message' : name === 'company' ? 'company' : 'text';
    const result = analyzeTextField(value, kind, { maxUrls: config.text.maxUrlsInMessage });
    textScores[name] = { entropy: result.entropy, points: result.points };
    if (result.points > 0) {
      signals.push({
        category: 'text',
        id: `text_${name}`,
        points: result.points,
        detail: result.signals.map((s) => s.id).join(', '),
      });
    }
  }
  const nameish = ['firstname', 'lastname', 'company'].map((k) => (submission.fields[k] || '').toLowerCase()).filter(Boolean);
  if (nameish.length >= 2 && new Set(nameish).size === 1) {
    signals.push({ category: 'text', id: 'text_identical_fields', points: 15, detail: 'first name, last name and/or company are identical' });
  }

  // 7. Browser headers and UTM integrity
  signals.push(...tag('browser', evaluateBrowserSignals(submission.headers, config.browser).signals));
  const utmResult = evaluateUtmSignals({ utm: submission.utm, pageUri: submission.pageUri, browserConfig: config.browser });
  signals.push(...tag('utm', utmResult.signals));
  submission.utm = utmResult.utm;

  const decision = decideVerdict(signals, config.thresholds);
  return {
    status: 'evaluated',
    receivedAt,
    dryRun: config.dryRun,
    sandboxMode: config.sandboxMode,
    warnings,
    decision,
    signals,
    asn: { asn: asnInfo.asn, org: asnInfo.org, source: asnInfo.source },
    velocity,
    textScores,
    formGuid: form.formGuid,
    submission,
  };
}

export function buildHubSpotSubmission(ctx, config) {
  const s = ctx.submission;
  const allowed = new Set(config.hubspot.forwardFields.map((f) => f.toLowerCase()));
  const fields = Object.entries(s.fields)
    .filter(([name]) => allowed.has(name))
    .map(([name, value]) => ({ objectTypeId: '0-1', name, value }));
  const context = {};
  if (s.hutk) context.hutk = s.hutk;
  if (s.pageUri) context.pageUri = s.pageUri;
  if (s.pageName) context.pageName = s.pageName;
  if (s.ip) context.ipAddress = s.ip;
  const body = { submittedAt: String(Date.parse(ctx.receivedAt)), fields, context };
  if (s.legalConsentOptions) body.legalConsentOptions = s.legalConsentOptions;
  const secure = !isPlaceholderValue(config.hubspot.token);
  const portal = config.hubspot.portalId;
  const path = secure ? 'submissions/v3/integration/secure/submit' : 'submissions/v3/integration/submit';
  return {
    url: `${config.hubspot.formsBaseUrl.replace(/\/+$/, '')}/${path}/${encodeURIComponent(portal)}/${encodeURIComponent(ctx.formGuid || '')}`,
    secure,
    formGuid: ctx.formGuid || null,
    body,
    forwardedFields: fields.map((f) => f.name),
  };
}

/** POSTs to the HubSpot Forms API, honouring DRY_RUN and SANDBOX_MODE. */
export async function deliverToHubSpot(request, { config, fetchImpl, sleep = (ms) => new Promise((r) => setTimeout(r, ms)) }) {
  if (config.dryRun) return { mode: 'intercepted_dry_run', url: request.url, secure: request.secure };
  if (isPlaceholderValue(config.hubspot.portalId) || !request.formGuid) {
    throw new ShieldSafetyError('hubspot_not_configured', 'HubSpot portal ID or form GUID is not configured');
  }
  if (config.sandboxMode && String(config.hubspot.portalId) !== String(config.hubspot.sandboxPortalId)) {
    throw new ShieldSafetyError('sandbox_portal_mismatch', 'SANDBOX_MODE=true: HUBSPOT_PORTAL_ID must equal HUBSPOT_SANDBOX_PORTAL_ID');
  }
  const headers = { 'content-type': 'application/json' };
  if (request.secure) headers.authorization = `Bearer ${config.hubspot.token}`;
  for (let attempt = 0; attempt < 2; attempt += 1) {
    const response = await fetchImpl(request.url, { method: 'POST', headers, body: JSON.stringify(request.body) });
    if ((response.status === 429 || response.status >= 500) && attempt === 0) {
      await sleep(1000);
      continue;
    }
    const text = await response.text();
    if (response.ok) return { mode: 'delivered', status: response.status, environment: config.sandboxMode ? 'sandbox' : 'production' };
    let errorTypes = [];
    try {
      errorTypes = (JSON.parse(text).errors || []).map((e) => e.errorType).filter(Boolean).slice(0, 5);
    } catch {
      errorTypes = [];
    }
    return { mode: 'rejected_by_hubspot', status: response.status, errorTypes };
  }
  return { mode: 'rejected_by_hubspot', status: 429, errorTypes: ['RATE_LIMITED'] };
}

export function buildQuarantineRecord(ctx, config, { id = crypto.randomUUID(), reasonOverride = null } = {}) {
  const s = ctx.submission;
  return {
    id,
    receivedAt: ctx.receivedAt,
    verdict: ctx.decision.verdict,
    reason: reasonOverride || ctx.decision.reason,
    score: ctx.decision.score,
    signals: ctx.signals.map((sig) => ({ category: sig.category, id: sig.id, points: sig.points, hard: sig.hard || null, detail: sig.detail })),
    email: s.email,
    emailDomain: emailDomainOf(s.email),
    fields: Object.fromEntries(Object.entries(s.fields).map(([k, v]) => [k, v.slice(0, 2000)])),
    ipHash: hashIdentifier(s.ip, config.quarantine.hashSalt),
    ip: config.quarantine.storeRawIp ? s.ip : null,
    asn: ctx.asn,
    userAgent: s.headers['user-agent'] || null,
    origin: s.headers.origin || null,
    pageUri: s.pageUri || null,
    utm: s.utm,
    formGuid: ctx.formGuid,
    releasable: ctx.decision.verdict !== 'block' || !ctx.signals.some((sig) => sig.id === 'honeypot_filled'),
    release: {
      hubspot: buildHubSpotSubmission({ ...ctx, submission: { ...s, ip: config.quarantine.storeRawIp ? s.ip : '' } }, config),
    },
  };
}

function quarantineSummaryText(record) {
  const top = record.signals
    .slice()
    .sort((a, b) => b.points - a.points)
    .slice(0, 4)
    .map((s) => `${s.id} (+${s.points})`)
    .join(', ');
  return `Form submission ${record.verdict.toUpperCase()} (score ${record.score}) from @${record.emailDomain || 'unknown'}: ${top || 'no signals'}`;
}

export async function deliverQuarantineWebhook(record, { config, fetchImpl }) {
  const url = config.quarantine.webhookUrl;
  if (isPlaceholderValue(url)) return { mode: 'not_configured' };
  if (!/^https:\/\//i.test(url)) return { mode: 'refused_non_https' };
  if (config.dryRun) return { mode: 'intercepted_dry_run' };
  const isSlack = url.startsWith('https://hooks.slack.com/');
  const { release, ...withoutRelease } = record;
  const payload = isSlack
    ? { text: quarantineSummaryText(record) }
    : { type: 'hubspot_form_quarantine', summary: quarantineSummaryText(record), record: withoutRelease };
  const response = await fetchImpl(url, { method: 'POST', headers: { 'content-type': 'application/json' }, body: JSON.stringify(payload) });
  return { mode: response.ok ? 'sent' : 'failed', status: response.status };
}

export async function quarantineStage(ctx, { config, fetchImpl, reasonOverride = null, recordId }) {
  if (ctx.status !== 'evaluated' && ctx.status !== 'delivery_failed') return ctx;
  const record = buildQuarantineRecord(ctx, config, { reasonOverride, ...(recordId ? { id: recordId } : {}) });
  let webhook;
  try {
    webhook = await deliverQuarantineWebhook(record, { config, fetchImpl });
  } catch (err) {
    webhook = { mode: 'failed', error: String(err && err.message).slice(0, 200) };
  }
  return { ...ctx, status: 'quarantined', quarantine: { record, webhook } };
}

export async function hubspotStage(ctx, { config, fetchImpl, sleep }) {
  if (ctx.status !== 'evaluated' || ctx.decision.verdict !== 'allow') return ctx;
  const request = buildHubSpotSubmission(ctx, config);
  try {
    const result = await deliverToHubSpot(request, { config, fetchImpl, ...(sleep ? { sleep } : {}) });
    if (result.mode === 'delivered' || result.mode === 'intercepted_dry_run') {
      return { ...ctx, status: 'forwarded', hubspot: { ...result, forwardedFields: request.forwardedFields } };
    }
    return quarantineStage({ ...ctx, status: 'delivery_failed', hubspot: result }, { config, fetchImpl, reasonOverride: `hubspot_${result.mode}` });
  } catch (err) {
    const code = err.code || 'delivery_error';
    return quarantineStage(
      { ...ctx, status: 'delivery_failed', hubspot: { mode: 'error', code } },
      { config, fetchImpl, reasonOverride: `hubspot_${code}` },
    );
  }
}

/** The browser-facing response. Rejections are silent by default so bots learn nothing. */
export function clientResponse(ctx, config) {
  if (ctx.status === 'error') return { httpStatus: 503, body: { ok: false, status: 'unavailable' } };
  const accepted = ctx.status === 'forwarded';
  if (accepted || config.silentReject) return { httpStatus: 200, body: { ok: true, status: 'received' } };
  const rateLimited = (ctx.signals || []).some((s) => s.id === 'velocity_ip_exceeded');
  return rateLimited
    ? { httpStatus: 429, body: { ok: false, status: 'rate_limited' } }
    : { httpStatus: 422, body: { ok: false, status: 'rejected' } };
}

/** Operator-facing summary (logs, n8n execution data, tests). Contains no raw email or IP. */
export function operatorSummary(ctx) {
  return {
    status: ctx.status,
    reason: ctx.reason || ctx.decision?.reason || null,
    dryRun: ctx.dryRun,
    sandboxMode: ctx.sandboxMode,
    verdict: ctx.decision?.verdict || null,
    score: ctx.decision?.score ?? null,
    signals: (ctx.signals || []).map((s) => `${s.category}:${s.id}:+${s.points}${s.hard ? `:${s.hard}` : ''}`),
    emailDomain: ctx.submission ? emailDomainOf(ctx.submission.email) : null,
    asn: ctx.asn || null,
    hubspot: ctx.hubspot || null,
    quarantineId: ctx.quarantine?.record?.id || null,
    quarantineWebhook: ctx.quarantine?.webhook?.mode || null,
    warnings: ctx.warnings || [],
    errors: ctx.errors || [],
  };
}

/** Node.js mirror of the n8n workflow: Evaluate -> IF allow -> HubSpot | Quarantine -> Respond. */
export async function processSubmission(input, deps) {
  let ctx = await evaluateStage(input, deps);
  if (ctx.status === 'evaluated') {
    ctx = ctx.decision.verdict === 'allow' ? await hubspotStage(ctx, deps) : await quarantineStage(ctx, deps);
  }
  return { ctx, response: clientResponse(ctx, deps.config), summary: operatorSummary(ctx) };
}
