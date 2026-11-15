/**
 * Test suite (node --test). No network: HTTP goes through a recording fetch stub,
 * the Express app listens on an ephemeral localhost port, and the n8n Code nodes
 * are executed in-process and compared with the Express mirror.
 */
import { test, describe, before, after } from 'node:test';
import assert from 'node:assert/strict';
import fs from 'node:fs';
import os from 'node:os';
import path from 'node:path';
import { createRequire } from 'node:module';
import { fileURLToPath } from 'node:url';

import { isPlaceholderValue, loadShieldConfig, parseFlag, validateShieldConfig } from '../src/core/config.js';
import { canonicalMailbox, isValidEmailSyntax, matchDisposableDomain } from '../src/core/disposableDomains.js';
import { analyzeTextField, isMostlyLatin, shannonEntropy } from '../src/core/textHeuristics.js';
import { evaluateIpSignals, ipMatchesRule, isPrivateOrReservedIp, lookupAsn } from '../src/core/ipReputation.js';
import { evaluateBrowserSignals, evaluateUtmSignals } from '../src/core/browserSignals.js';
import { createVelocityTracker } from '../src/core/velocity.js';
import {
  buildHubSpotSubmission,
  clientResponse,
  decideVerdict,
  evaluateStage,
  issueRenderToken,
  processSubmission,
} from '../src/core/shield.js';
import { createApp, runSimulation } from '../src/server.js';
import { createQuarantineStore } from '../src/quarantineStore.js';
import { buildWorkflow, serializeWorkflow } from '../scripts/build-n8n-workflow.js';

const ROOT = path.resolve(path.dirname(fileURLToPath(import.meta.url)), '..');
const FIXTURES = JSON.parse(fs.readFileSync(path.join(ROOT, 'fixtures', 'sample-submissions.json'), 'utf8'));
const NOW = Date.parse('2026-11-15T12:00:00Z');
const CHROME_HEADERS = FIXTURES[0].headers;

function recordingFetch(handler = () => ({ status: 200, body: {} })) {
  const calls = [];
  const fetchImpl = async (url, init = {}) => {
    calls.push({ url, method: init.method || 'GET', headers: init.headers || {}, body: init.body ? JSON.parse(init.body) : undefined });
    const { status = 200, body = {} } = (await handler(calls[calls.length - 1])) || {};
    const text = typeof body === 'string' ? body : JSON.stringify(body);
    return { ok: status >= 200 && status < 300, status, headers: { get: () => null }, text: async () => text, json: async () => JSON.parse(text) };
  };
  return { fetchImpl, calls };
}

function cfg(overrides = {}) {
  const config = loadShieldConfig({ QUARANTINE_HASH_SALT: 'test-salt', ...overrides });
  config.ip.clientIpHeader = 'none';
  return config;
}

function cleanBody(extra = {}) {
  return { ...FIXTURES[0].body, _rendered_at: String(NOW - 30000), ...extra };
}

async function evaluate(body, { headers = CHROME_HEADERS, ip = '203.0.113.10', config = cfg(), tracker, fetchImpl } = {}) {
  return evaluateStage(
    { body, headers, socketIp: ip, query: {} },
    { config, velocityTracker: tracker || createVelocityTracker({}), fetchImpl: fetchImpl || recordingFetch().fetchImpl, now: NOW },
  );
}

const ids = (ctx) => ctx.signals.map((s) => s.id);

describe('configuration is fail-safe', () => {
  test('DRY_RUN and SANDBOX_MODE default on; only explicit false disables', () => {
    const c = loadShieldConfig({});
    assert.equal(c.dryRun, true);
    assert.equal(c.sandboxMode, true);
    assert.equal(c.ip.asnProvider, 'none');
    assert.equal(loadShieldConfig({ DRY_RUN: 'flase' }).dryRun, true);
    assert.equal(loadShieldConfig({ DRY_RUN: 'false' }).dryRun, false);
    assert.equal(parseFlag('OFF', true), false);
    assert.equal(loadShieldConfig({ ASN_LOOKUP_PROVIDER: 'something-else' }).ip.asnProvider, 'none');
  });

  test('placeholders are recognised and live mode refuses them', () => {
    assert.equal(isPlaceholderValue('your_hubspot_private_app_token_here'), true);
    const { errors } = validateShieldConfig(loadShieldConfig({ DRY_RUN: 'false', HUBSPOT_PORTAL_ID: 'your_hubspot_portal_id_here' }));
    assert.ok(errors.some((e) => e.includes('HUBSPOT_PORTAL_ID')));
    assert.ok(errors.some((e) => e.includes('HUBSPOT_FORM_GUID')));
    assert.ok(errors.some((e) => e.includes('QUARANTINE_HASH_SALT')));
    assert.ok(errors.some((e) => e.includes('HUBSPOT_SANDBOX_PORTAL_ID')));
    const thresholds = validateShieldConfig(loadShieldConfig({ QUARANTINE_SCORE_THRESHOLD: '90', BLOCK_SCORE_THRESHOLD: '80' }));
    assert.ok(thresholds.errors.some((e) => e.includes('lower than')));
  });

  test('an invalid configuration returns 503 to the browser and forwards nothing', async () => {
    const { fetchImpl, calls } = recordingFetch();
    const result = await processSubmission(
      { body: cleanBody(), headers: CHROME_HEADERS, socketIp: '203.0.113.10' },
      { config: cfg({ DRY_RUN: 'false' }), velocityTracker: createVelocityTracker({}), fetchImpl, now: NOW },
    );
    assert.equal(result.ctx.status, 'error');
    assert.equal(result.response.httpStatus, 503);
    assert.equal(calls.length, 0);
  });
});

describe('disposable email detection', () => {
  test('bundled list, subdomains and runtime extras', () => {
    assert.equal(matchDisposableDomain('mailinator.com'), 'mailinator.com');
    assert.equal(matchDisposableDomain('inbox.guerrillamail.com'), 'guerrillamail.com');
    assert.equal(matchDisposableDomain('acme.example'), null);
    assert.equal(matchDisposableDomain('throwaway.example', ['throwaway.example']), 'throwaway.example');
  });

  test('syntax checks and canonical mailbox collapsing', () => {
    assert.equal(isValidEmailSyntax('jane.doe@acme.example'), true);
    for (const bad of ['jane', 'jane@', '@acme.example', 'jane..doe@acme.example', 'jane@acme', '.jane@acme.example']) {
      assert.equal(isValidEmailSyntax(bad), false, bad);
    }
    assert.equal(canonicalMailbox('J.a.n.e+promo@gmail.com'), 'jane@gmail.com');
    assert.equal(canonicalMailbox('jane+x@acme.example'), 'jane@acme.example');
  });

  test('disposable addresses are blocked by default and quarantined when configured', async () => {
    const blocked = await evaluate(cleanBody({ email: 'x@yopmail.com' }));
    assert.equal(blocked.decision.verdict, 'block');
    const soft = await evaluate(cleanBody({ email: 'x@yopmail.com' }), { config: cfg({ DISPOSABLE_EMAIL_ACTION: 'quarantine' }) });
    assert.equal(soft.decision.verdict, 'quarantine');
    const allowlisted = await evaluate(cleanBody({ email: 'qa@yopmail.com' }), { config: cfg({ ALLOWLIST_EMAIL_DOMAINS: 'yopmail.com' }) });
    assert.ok(!ids(allowlisted).includes('email_disposable'));
  });
});

describe('gibberish, entropy and spam heuristics', () => {
  test('Shannon entropy', () => {
    assert.equal(shannonEntropy(''), 0);
    assert.equal(shannonEntropy('aaaa'), 0);
    assert.equal(shannonEntropy('abcd'), 2);
    assert.ok(shannonEntropy('Kx9#pQ2!vL7@') > 3.5);
  });

  test('flags keyboard smashes, consonant runs, repeats, digits and random tokens', () => {
    assert.ok(analyzeTextField('asdfgh', 'name').signals.some((s) => s.id === 'keyboard_sequence'));
    assert.ok(analyzeTextField('xkcdvbnm', 'name').signals.some((s) => s.id === 'consonant_run'));
    assert.ok(analyzeTextField('Joooooohn', 'name').signals.some((s) => s.id === 'repeated_characters'));
    assert.ok(analyzeTextField('J0hn5', 'name').signals.some((s) => s.id === 'digits_in_name'));
    assert.ok(analyzeTextField('Zq8Lm2Xv9Pk4Rt7', 'company').signals.some((s) => s.id === 'random_token'));
    assert.ok(analyzeTextField('qwrtzpl', 'name').points >= 30);
  });

  test('real names in many languages score zero', () => {
    for (const name of ['Jane', 'Siobhán', 'Wojciech', 'Grzegorz', 'Brzęczyszczykiewicz', 'Nguyễn Thị Minh', 'Oluwaseun', 'Xiaoming', 'Björn', 'Krzysztof', 'Ngozi', 'Mxolisi']) {
      assert.equal(analyzeTextField(name, 'name').points, 0, name);
    }
    for (const name of ['李小龍', 'Дмитрий', 'محمد', 'さくら', 'Αλέξανδρος']) {
      assert.equal(isMostlyLatin(name), false, name);
      assert.equal(analyzeTextField(name, 'name').points, 0, name);
    }
  });

  test('spam phrases, LLM artifacts, templates and link stuffing in messages', () => {
    const r = analyzeTextField(FIXTURES[4].body.message, 'message');
    const found = r.signals.map((s) => s.id);
    for (const id of ['llm_artifact', 'seo_pitch', 'unfilled_template', 'too_many_urls']) assert.ok(found.includes(id), id);
    assert.equal(r.points, 45);
    assert.equal(analyzeTextField(FIXTURES[0].body.message, 'message').points, 0);
    assert.ok(analyzeTextField('<a href="https://spam.example">click</a>', 'message').signals.some((s) => s.id === 'markup_links'));
  });
});

describe('IP and ASN screening', () => {
  test('CIDR matching and reserved ranges', () => {
    assert.equal(ipMatchesRule('198.51.100.23', '198.51.100.0/24'), true);
    assert.equal(ipMatchesRule('198.51.101.1', '198.51.100.0/24'), false);
    assert.equal(ipMatchesRule('2001:db8::1', '2001:db8::1'), true);
    assert.equal(isPrivateOrReservedIp('10.1.2.3'), true);
    assert.equal(isPrivateOrReservedIp('8.8.8.8'), false);
  });

  test('header ASN provider flags datacenter networks', async () => {
    const ipConfig = cfg({ ASN_LOOKUP_PROVIDER: 'header' }).ip;
    const info = await lookupAsn({ ip: '8.8.8.8', headers: { 'X-Client-ASN': 'AS16509' }, ipConfig });
    assert.equal(info.asn, 16509);
    const { signals } = evaluateIpSignals({ ip: '8.8.8.8', asnInfo: info, ipConfig });
    assert.equal(signals[0].id, 'asn_datacenter');
  });

  test('ipinfo provider parses ASN and privacy data; failures never throw', async () => {
    const ipConfig = cfg({ ASN_LOOKUP_PROVIDER: 'ipinfo', IPINFO_TOKEN: 'test-token' }).ip;
    const { fetchImpl, calls } = recordingFetch(() => ({ body: { org: 'AS14061 DigitalOcean, LLC', privacy: { vpn: true, hosting: true } } }));
    const info = await lookupAsn({ ip: '8.8.8.8', ipConfig, fetchImpl });
    assert.equal(info.asn, 14061);
    assert.match(calls[0].url, /^https:\/\/ipinfo\.io\/8\.8\.8\.8\/json\?token=test-token$/);
    const ipSignals = evaluateIpSignals({ ip: '8.8.8.8', asnInfo: info, ipConfig }).signals.map((s) => s.id);
    assert.deepEqual(ipSignals, ['asn_datacenter', 'ip_anonymizer']);
    const failing = await lookupAsn({ ip: '8.8.8.8', ipConfig, fetchImpl: async () => { throw new Error('network down'); } });
    assert.equal(failing.source, 'error');
  });

  test('default provider makes no outbound call', async () => {
    const { fetchImpl, calls } = recordingFetch();
    await evaluate(cleanBody(), { fetchImpl });
    assert.equal(calls.length, 0);
  });

  test('blocklist is a hard block; allowlist skips IP velocity', async () => {
    const blocked = await evaluate(cleanBody(), { config: cfg({ IP_BLOCKLIST_CIDRS: '203.0.113.0/24' }) });
    assert.equal(blocked.decision.verdict, 'block');
    const config = cfg({ IP_ALLOWLIST_CIDRS: '203.0.113.10', VELOCITY_MAX_PER_IP: '1', VELOCITY_MAX_PER_EMAIL: '0', VELOCITY_MAX_PER_EMAIL_DOMAIN: '0' });
    const tracker = createVelocityTracker({});
    await evaluate(cleanBody(), { config, tracker });
    const second = await evaluate(cleanBody(), { config, tracker });
    assert.ok(!ids(second).includes('velocity_ip_exceeded'));
  });
});

describe('browser and UTM signals', () => {
  const browser = cfg().browser;

  test('automation user agents, missing headers and Fetch Metadata', () => {
    assert.ok(evaluateBrowserSignals({ 'user-agent': 'curl/8.4.0' }, browser).signals.some((s) => s.id === 'ua_automation'));
    assert.ok(evaluateBrowserSignals({}, browser).signals.some((s) => s.id === 'ua_missing'));
    const noFetch = evaluateBrowserSignals({ 'user-agent': CHROME_HEADERS['user-agent'], 'accept-language': 'en' }, browser).signals.map((s) => s.id);
    assert.ok(noFetch.includes('fetch_metadata_missing'));
    assert.deepEqual(evaluateBrowserSignals(CHROME_HEADERS, browser).signals, []);
  });

  test('Origin / Referer allowlist', () => {
    const strict = cfg({ ALLOWED_ORIGINS: 'https://www.example.com' }).browser;
    assert.deepEqual(evaluateBrowserSignals(CHROME_HEADERS, strict).signals, []);
    const foreign = evaluateBrowserSignals({ ...CHROME_HEADERS, origin: 'https://evil.example', referer: '' }, strict).signals;
    assert.equal(foreign[0].id, 'origin_not_allowed');
    const none = evaluateBrowserSignals({ ...CHROME_HEADERS, origin: undefined, referer: undefined }, strict).signals;
    assert.equal(none[0].id, 'origin_missing');
  });

  test('UTM integrity: injection, incomplete, mismatch, required', () => {
    const inj = evaluateUtmSignals({ utm: { utm_source: '<script>alert(1)</script>' }, browserConfig: browser });
    assert.equal(inj.signals[0].id, 'utm_injection');
    assert.equal(evaluateUtmSignals({ utm: { utm_medium: 'cpc' }, browserConfig: browser }).signals[0].id, 'utm_incomplete');
    const mismatch = evaluateUtmSignals({ utm: { utm_source: 'bing' }, pageUri: 'https://www.example.com/?utm_source=google', browserConfig: browser });
    assert.ok(mismatch.signals.some((s) => s.id === 'utm_mismatch'));
    const required = evaluateUtmSignals({ utm: {}, browserConfig: cfg({ REQUIRE_UTM: 'true' }).browser });
    assert.equal(required.signals[0].id, 'utm_missing');
    assert.deepEqual(evaluateUtmSignals({ utm: FIXTURES[0].body, pageUri: FIXTURES[0].body.pageUri, browserConfig: browser }).signals, []);
  });
});

describe('velocity and timing', () => {
  test('sliding window counts per key and expires', () => {
    const backing = {};
    const t = createVelocityTracker(backing, { windowSeconds: 60 });
    assert.deepEqual(t.hit(['ip:a'], 0), { 'ip:a': 1 });
    assert.deepEqual(t.hit(['ip:a'], 30000), { 'ip:a': 2 });
    assert.deepEqual(t.hit(['ip:a'], 61000), { 'ip:a': 2 });
    assert.equal(t.count('ip:a', 200000), 0);
    assert.deepEqual(backing, {});
  });

  test('IP flood blocks; a domain burst quarantines; free-mail domains get a higher limit', async () => {
    const config = cfg({ VELOCITY_MAX_PER_IP: '2', VELOCITY_MAX_PER_EMAIL_DOMAIN: '2', VELOCITY_MAX_PER_EMAIL: '0' });
    const tracker = createVelocityTracker({});
    let last;
    for (let i = 0; i < 3; i += 1) last = await evaluate(cleanBody({ email: `user${i}@acme.example` }), { config, tracker, ip: `203.0.113.${i + 1}` });
    assert.ok(ids(last).includes('velocity_domain_exceeded'));
    assert.equal(last.decision.verdict, 'quarantine');
    for (let i = 0; i < 3; i += 1) last = await evaluate(cleanBody({ email: `p${i}@gmail.com` }), { config, tracker, ip: '203.0.113.99' });
    assert.ok(ids(last).includes('velocity_ip_exceeded'));
    assert.ok(!ids(last).includes('velocity_domain_exceeded'));
  });

  test('honeypot, fill-too-fast and signed render tokens', async () => {
    assert.equal((await evaluate(cleanBody({ fax_number: '555' }))).decision.verdict, 'block');
    assert.ok(ids(await evaluate(cleanBody({ _rendered_at: String(NOW - 1000) }))).includes('filled_too_fast'));
    assert.ok(ids(await evaluate(cleanBody({ _rendered_at: undefined }))).includes('render_timestamp_missing'));
    const secretConfig = cfg({ FORM_TOKEN_SECRET: 'render-secret-for-tests' });
    const { renderedAt, token } = issueRenderToken('render-secret-for-tests', NOW - 30000);
    const signed = await evaluate(cleanBody({ _rendered_at: renderedAt, _render_token: token }), { config: secretConfig });
    assert.ok(!ids(signed).includes('render_token_invalid'));
    const forged = await evaluate(cleanBody({ _rendered_at: renderedAt, _render_token: 'f'.repeat(64) }), { config: secretConfig });
    assert.ok(ids(forged).includes('render_token_invalid'));
  });

  test('verdict thresholds and hard rules', () => {
    const t = { quarantine: 40, block: 80 };
    assert.equal(decideVerdict([{ points: 39 }], t).verdict, 'allow');
    assert.equal(decideVerdict([{ points: 40 }], t).verdict, 'quarantine');
    assert.equal(decideVerdict([{ points: 50 }, { points: 30 }], t).verdict, 'block');
    assert.equal(decideVerdict([{ id: 'x', points: 5, hard: 'quarantine' }], t).verdict, 'quarantine');
    assert.equal(decideVerdict([{ id: 'y', points: 1, hard: 'block' }], t).reason, 'hard_rule:y');
  });
});

describe('HubSpot forwarding and quarantine', () => {
  test('payload shape: allowlisted fields, context with IP and hutk, consent passthrough, secure endpoint with a token', async () => {
    const consent = { consent: { consentToProcess: true, text: 'I agree' } };
    const ctx = await evaluate(cleanBody({ legalConsentOptions: consent, secret_internal_field: 'x' }), {
      config: cfg({ HUBSPOT_PORTAL_ID: '1234567', HUBSPOT_FORM_GUID: '00000000-0000-4000-8000-000000000000', HUBSPOT_PRIVATE_APP_TOKEN: 'test-token' }),
    });
    const request = buildHubSpotSubmission(ctx, cfg({ HUBSPOT_PORTAL_ID: '1234567', HUBSPOT_PRIVATE_APP_TOKEN: 'test-token' }));
    assert.equal(request.url, 'https://api.hsforms.com/submissions/v3/integration/secure/submit/1234567/00000000-0000-4000-8000-000000000000');
    assert.deepEqual(request.forwardedFields.sort(), ['company', 'email', 'firstname', 'jobtitle', 'lastname', 'message']);
    assert.equal(request.body.context.ipAddress, '203.0.113.10');
    assert.equal(request.body.context.hutk, FIXTURES[0].body.hutk);
    assert.deepEqual(request.body.legalConsentOptions, consent);
    assert.ok(request.body.fields.every((f) => f.objectTypeId === '0-1'));
    const unsecured = buildHubSpotSubmission(ctx, cfg({ HUBSPOT_PORTAL_ID: '1234567' }));
    assert.match(unsecured.url, /\/submissions\/v3\/integration\/submit\//);
  });

  const live = {
    DRY_RUN: 'false',
    HUBSPOT_PORTAL_ID: '1234567',
    HUBSPOT_SANDBOX_PORTAL_ID: '1234567',
    HUBSPOT_FORM_GUID: '00000000-0000-4000-8000-000000000000',
  };

  test('DRY_RUN never calls HubSpot or the quarantine webhook', async () => {
    const { fetchImpl, calls } = recordingFetch();
    const config = cfg({ QUARANTINE_WEBHOOK_URL: 'https://hooks.slack.com/services/test/test/test' });
    const allowed = await processSubmission({ body: cleanBody(), headers: CHROME_HEADERS, socketIp: '203.0.113.10' }, { config, velocityTracker: createVelocityTracker({}), fetchImpl, now: NOW });
    assert.equal(allowed.ctx.hubspot.mode, 'intercepted_dry_run');
    const blocked = await processSubmission({ body: cleanBody({ website_url: 'x' }), headers: CHROME_HEADERS, socketIp: '203.0.113.10' }, { config, velocityTracker: createVelocityTracker({}), fetchImpl, now: NOW });
    assert.equal(blocked.ctx.quarantine.webhook.mode, 'intercepted_dry_run');
    assert.equal(calls.length, 0);
  });

  test('SANDBOX_MODE refuses a non-sandbox portal and quarantines instead of losing the lead', async () => {
    const { fetchImpl, calls } = recordingFetch();
    const config = cfg({ ...live, HUBSPOT_SANDBOX_PORTAL_ID: '7654321' });
    const r = await processSubmission({ body: cleanBody(), headers: CHROME_HEADERS, socketIp: '203.0.113.10' }, { config, velocityTracker: createVelocityTracker({}), fetchImpl, now: NOW });
    assert.equal(r.ctx.status, 'quarantined');
    assert.equal(r.ctx.quarantine.record.reason, 'hubspot_sandbox_portal_mismatch');
    assert.equal(r.ctx.quarantine.record.verdict, 'allow');
    assert.equal(calls.length, 0);
  });

  test('live sandbox delivery succeeds; HubSpot rejections fall back to quarantine', async () => {
    const ok = recordingFetch(() => ({ status: 200, body: { inlineMessage: 'Thanks' } }));
    const delivered = await processSubmission({ body: cleanBody(), headers: CHROME_HEADERS, socketIp: '203.0.113.10' }, { config: cfg(live), velocityTracker: createVelocityTracker({}), fetchImpl: ok.fetchImpl, now: NOW });
    assert.equal(delivered.ctx.hubspot.mode, 'delivered');
    assert.equal(ok.calls[0].method, 'POST');
    assert.equal(ok.calls[0].headers.authorization, undefined);

    const bad = recordingFetch(() => ({ status: 400, body: { errors: [{ errorType: 'INVALID_EMAIL' }] } }));
    const rejected = await processSubmission({ body: cleanBody(), headers: CHROME_HEADERS, socketIp: '203.0.113.10' }, { config: cfg(live), velocityTracker: createVelocityTracker({}), fetchImpl: bad.fetchImpl, now: NOW });
    assert.equal(rejected.ctx.status, 'quarantined');
    assert.equal(rejected.ctx.quarantine.record.reason, 'hubspot_rejected_by_hubspot');
    assert.deepEqual(rejected.ctx.hubspot.errorTypes, ['INVALID_EMAIL']);
  });

  test('quarantine records hash the IP, keep it out by default, and Slack gets a text summary', async () => {
    const { fetchImpl, calls } = recordingFetch(() => ({ status: 200, body: 'ok' }));
    const config = cfg({ ...live, QUARANTINE_WEBHOOK_URL: 'https://hooks.slack.com/services/test/test/test' });
    const r = await processSubmission({ body: cleanBody({ website_url: 'x' }), headers: CHROME_HEADERS, socketIp: '203.0.113.10' }, { config, velocityTracker: createVelocityTracker({}), fetchImpl, now: NOW });
    const rec = r.ctx.quarantine.record;
    assert.equal(rec.ip, null);
    assert.match(rec.ipHash, /^[0-9a-f]{24}$/);
    assert.equal(rec.releasable, false);
    assert.equal(rec.release.hubspot.body.context.ipAddress, undefined);
    assert.deepEqual(Object.keys(calls[0].body), ['text']);
    assert.match(calls[0].body.text, /BLOCK \(score 100\)/);
    const nonHttps = await processSubmission({ body: cleanBody({ website_url: 'x' }), headers: CHROME_HEADERS, socketIp: '203.0.113.10' }, { config: cfg({ ...live, QUARANTINE_WEBHOOK_URL: 'http://plain.example/hook' }), velocityTracker: createVelocityTracker({}), fetchImpl, now: NOW });
    assert.equal(nonHttps.ctx.quarantine.webhook.mode, 'refused_non_https');
  });

  test('silent reject: bots get the same response as real leads unless disabled', async () => {
    const ctx = { status: 'quarantined', signals: [{ id: 'velocity_ip_exceeded' }] };
    assert.deepEqual(clientResponse(ctx, cfg()), { httpStatus: 200, body: { ok: true, status: 'received' } });
    assert.equal(clientResponse(ctx, cfg({ SILENT_REJECT: 'false' })).httpStatus, 429);
    assert.equal(clientResponse({ status: 'quarantined', signals: [] }, cfg({ SILENT_REJECT: 'false' })).httpStatus, 422);
  });
});

describe('Express middleware', () => {
  let server;
  let base;
  let store;
  const tmp = fs.mkdtempSync(path.join(os.tmpdir(), 'shield-'));
  const adminToken = 'admin-token-for-tests-0123456789';

  before(async () => {
    store = createQuarantineStore({ filePath: path.join(tmp, 'quarantine.jsonl') });
    const { app } = createApp({
      env: { QUARANTINE_HASH_SALT: 'test-salt', ADMIN_API_TOKEN: adminToken, ALLOWED_ORIGINS: 'https://www.example.com', BODY_LIMIT: '8kb' },
      fetchImpl: recordingFetch().fetchImpl,
      quarantineStore: store,
      logger: () => {},
    });
    await new Promise((resolve) => {
      server = app.listen(0, '127.0.0.1', resolve);
    });
    base = `http://127.0.0.1:${server.address().port}`;
  });
  after(() => {
    server.close();
    fs.rmSync(tmp, { recursive: true, force: true });
  });

  const post = (body, headers = {}) =>
    fetch(`${base}/v1/submit`, { method: 'POST', headers: { ...CHROME_HEADERS, 'content-type': 'application/json', ...headers }, body: typeof body === 'string' ? body : JSON.stringify(body) });

  test('health endpoint reports safety flags', async () => {
    const res = await fetch(`${base}/healthz`);
    const body = await res.json();
    assert.equal(body.dryRun, true);
    assert.equal(body.sandboxMode, true);
  });

  test('CORS preflight only for allowed origins', async () => {
    const ok = await fetch(`${base}/v1/submit`, { method: 'OPTIONS', headers: { origin: 'https://www.example.com' } });
    assert.equal(ok.status, 204);
    assert.equal(ok.headers.get('access-control-allow-origin'), 'https://www.example.com');
    const bad = await fetch(`${base}/v1/submit`, { method: 'OPTIONS', headers: { origin: 'https://evil.example' } });
    assert.equal(bad.headers.get('access-control-allow-origin'), null);
  });

  test('clean JSON and urlencoded submissions are accepted', async () => {
    const res = await post(cleanBody({ _rendered_at: String(Date.now() - 30000) }));
    assert.deepEqual(await res.json(), { ok: true, status: 'received' });
    const form = new URLSearchParams({ email: 'ana@acme.example', firstname: 'Ana', _rendered_at: String(Date.now() - 30000) });
    const res2 = await fetch(`${base}/v1/submit`, { method: 'POST', headers: { ...CHROME_HEADERS, 'content-type': 'application/x-www-form-urlencoded' }, body: form });
    assert.equal(res2.status, 200);
  });

  test('a honeypot hit looks successful to the bot but lands in the review log', async () => {
    const before = store.size();
    const res = await post(cleanBody({ website_url: 'gotcha', _rendered_at: String(Date.now() - 30000) }));
    assert.deepEqual(await res.json(), { ok: true, status: 'received' });
    assert.equal(store.size(), before + 1);
    const line = fs.readFileSync(store.filePath, 'utf8').trim().split('\n').pop();
    assert.equal(JSON.parse(line).record.verdict, 'block');
  });

  test('malformed and oversized bodies', async () => {
    assert.equal((await post('{not json')).status, 400);
    assert.equal((await post({ message: 'x'.repeat(20000) })).status, 413);
  });

  test('admin review log requires the bearer token; releases respect DRY_RUN', async () => {
    assert.equal((await fetch(`${base}/admin/quarantine`)).status, 401);
    await post(cleanBody({ email: 'review@acme.example', message: 'As an AI language model, SEO services to rank your website. [Your Name]', _rendered_at: String(Date.now() - 30000) }));
    const list = await (await fetch(`${base}/admin/quarantine?verdict=quarantine`, { headers: { authorization: `Bearer ${adminToken}` } })).json();
    const record = list.records.find((r) => r.email === 'review@acme.example');
    assert.ok(record);
    assert.equal(record.release, undefined);
    const release = await fetch(`${base}/admin/quarantine/${record.id}/release`, { method: 'POST', headers: { authorization: `Bearer ${adminToken}` } });
    assert.equal((await release.json()).mode, 'intercepted_dry_run');
    assert.equal(store.get(record.id).releasedAt, null);
    const honeypot = store.list({ verdict: 'block' })[0];
    assert.equal((await fetch(`${base}/admin/quarantine/${honeypot.id}/release`, { method: 'POST', headers: { authorization: `Bearer ${adminToken}` } })).status, 422);
  });

  test('admin endpoints do not exist without a real ADMIN_API_TOKEN', async () => {
    const { app } = createApp({ env: { ADMIN_API_TOKEN: 'your_admin_api_token_here' }, quarantineStore: store, logger: () => {} });
    const s = await new Promise((resolve) => {
      const srv = app.listen(0, '127.0.0.1', () => resolve(srv));
    });
    const res = await fetch(`http://127.0.0.1:${s.address().port}/admin/quarantine`);
    assert.equal(res.status, 404);
    s.close();
  });

  test('review log retention drops old records on reopen', () => {
    const file = path.join(tmp, 'retention.jsonl');
    const old = { event: 'quarantined', record: { id: 'old', receivedAt: '2020-01-01T00:00:00Z', verdict: 'block' } };
    const fresh = { event: 'quarantined', record: { id: 'new', receivedAt: new Date().toISOString(), verdict: 'block' } };
    fs.writeFileSync(file, `${JSON.stringify(old)}\n${JSON.stringify(fresh)}\n`);
    const reopened = createQuarantineStore({ filePath: file, retentionDays: 30 });
    assert.equal(reopened.get('old'), null);
    assert.ok(reopened.get('new'));
  });
});

describe('fixtures end to end', () => {
  test('every fixture gets its expected verdict and nothing is sent anywhere', async () => {
    const { fetchImpl, calls } = recordingFetch();
    const results = await runSimulation({ env: { QUARANTINE_WEBHOOK_URL: 'https://hooks.slack.com/services/test/test/test' }, fetchImpl });
    for (const r of results) assert.equal(r.verdict, r.expected, r.name);
    assert.equal(calls.length, 0);
    assert.ok(results.every((r) => r.client.httpStatus === 200));
  });
});

describe('n8n workflow parity', () => {
  const file = path.join(ROOT, 'workflows', 'hubspot-honeypot-shield.json');
  const committed = fs.readFileSync(file, 'utf8');
  const workflow = JSON.parse(committed);

  test('structure, connections and no embedded credentials', () => {
    const names = new Set(workflow.nodes.map((n) => n.name));
    assert.equal(names.size, workflow.nodes.length);
    for (const [from, out] of Object.entries(workflow.connections)) {
      assert.ok(names.has(from));
      for (const branch of out.main) for (const l of branch) assert.ok(names.has(l.node), l.node);
    }
    assert.ok(workflow.nodes.every((n) => !n.credentials));
    assert.ok(!/sk-[A-Za-z0-9]{20,}|pat-(?:na|eu)\d-[0-9a-f-]{20,}|xox[abpr]-[0-9A-Za-z-]{10,}|hooks\.slack\.com\/services\/T[0-9A-Z]{6,}/.test(committed));
    assert.equal(workflow.active, false);
  });

  test('committed workflow equals a fresh build from src/core/', () => {
    assert.equal(serializeWorkflow(buildWorkflow()), committed);
  });

  async function runWorkflow({ body, headers, env, staticData }) {
    const AsyncFunction = Object.getPrototypeOf(async () => {}).constructor;
    const requireFn = createRequire(import.meta.url);
    const helpers = { httpRequest: async () => ({ statusCode: 200, headers: {}, body: '{}' }) };
    const byName = Object.fromEntries(workflow.nodes.map((n) => [n.name, n]));
    let current = 'Form Submission Webhook';
    let items = [{ json: { headers, query: {}, body } }];
    for (;;) {
      const out = workflow.connections[current];
      if (!out) break;
      let next = out.main[0][0].node;
      if (byName[current].type === 'n8n-nodes-base.if') {
        const verdict = items[0].json.decision ? items[0].json.decision.verdict : 'error';
        next = (verdict === 'allow' ? out.main[0] : out.main[1])[0].node;
      }
      current = next;
      const node = byName[current];
      if (node.type !== 'n8n-nodes-base.code') continue;
      const fn = new AsyncFunction('$input', '$env', '$getWorkflowStaticData', 'require', node.parameters.jsCode);
      items = await fn.call({ helpers }, { first: () => items[0], all: () => items }, env, () => staticData, requireFn);
    }
    assert.equal(byName[current].type, 'n8n-nodes-base.respondToWebhook');
    return items[0].json;
  }

  for (const fixture of FIXTURES.filter((f) => !f.repeat)) {
    test(`n8n matches the Express mirror: ${fixture.name}`, async () => {
      const env = { QUARANTINE_HASH_SALT: 'test-salt', CLIENT_IP_HEADER: 'x-real-ip', ...(fixture.env || {}) };
      const body = { ...fixture.body, _rendered_at: String(Date.now() - (fixture.secondsToFill ?? 20) * 1000) };
      const staticData = {};
      const n8n = await runWorkflow({ body, headers: { ...fixture.headers, 'x-real-ip': fixture.ip }, env, staticData });
      const config = loadShieldConfig(env);
      config.ip.clientIpHeader = 'none';
      const mirror = await processSubmission({ body, headers: fixture.headers, socketIp: fixture.ip }, { config, velocityTracker: createVelocityTracker({}), fetchImpl: recordingFetch().fetchImpl, now: Date.now() });
      assert.equal(n8n.summary.verdict, fixture.expectedVerdict);
      assert.equal(n8n.httpStatus, mirror.response.httpStatus);
      assert.deepEqual(n8n.body, mirror.response.body);
      for (const key of ['status', 'verdict', 'score', 'signals']) assert.deepEqual(n8n.summary[key], mirror.summary[key], key);
      assert.ok(Object.keys(staticData.velocity).length >= 1);
      assert.equal(staticData.quarantineLog.length, fixture.expectedVerdict === 'allow' ? 0 : 1);
    });
  }
});
