#!/usr/bin/env node
/**
 * Express middleware that sits in front of HubSpot form submissions.
 *
 *   GET  /healthz                              liveness + safety flags
 *   GET  /v1/form-token                        signed render timestamp for the form (honeypot timing)
 *   POST /v1/submit                            score a submission; forward clean leads, quarantine the rest
 *   GET  /admin/quarantine                     review log (Bearer ADMIN_API_TOKEN)
 *   POST /admin/quarantine/:id/release         forward a reviewed submission to HubSpot (Bearer ADMIN_API_TOKEN)
 *
 *   node src/server.js --simulate              run fixtures through the shield (DRY_RUN forced on)
 */
import crypto from 'node:crypto';
import fs from 'node:fs';
import path from 'node:path';
import { fileURLToPath, pathToFileURL } from 'node:url';
import express from 'express';
import { isPlaceholderValue, loadShieldConfig, validateShieldConfig } from './core/config.js';
import { createVelocityTracker } from './core/velocity.js';
import { deliverToHubSpot, issueRenderToken, operatorSummary, processSubmission } from './core/shield.js';
import { createQuarantineStore } from './quarantineStore.js';

export const ROOT_DIR = path.resolve(path.dirname(fileURLToPath(import.meta.url)), '..');

/** Minimal .env loader (no dependency). Existing environment variables win. */
export function loadDotEnvFile(filePath = path.join(ROOT_DIR, '.env'), target = process.env) {
  if (!fs.existsSync(filePath)) return false;
  for (const line of fs.readFileSync(filePath, 'utf8').split(/\r?\n/)) {
    const match = line.match(/^\s*(?:export\s+)?([A-Za-z_][A-Za-z0-9_]*)\s*=\s*(.*)\s*$/);
    if (!match) continue;
    let value = match[2];
    if (/^(['"]).*\1$/.test(value)) value = value.slice(1, -1);
    else value = value.replace(/\s+#.*$/, '');
    if (target[match[1]] === undefined) target[match[1]] = value;
  }
  return true;
}

function log(level, msg, data = {}) {
  const line = JSON.stringify({ ts: new Date().toISOString(), level, msg, ...data });
  (level === 'error' || level === 'warn' ? process.stderr : process.stdout).write(`${line}\n`);
}

function parseTrustProxy(value) {
  if (value === undefined || value === '') return 'loopback';
  if (/^(true|false)$/i.test(value)) return value.toLowerCase() === 'true';
  if (/^\d+$/.test(value)) return Number(value);
  return value;
}

function safeEqual(a, b) {
  const ab = Buffer.from(String(a));
  const bb = Buffer.from(String(b));
  return ab.length === bb.length && crypto.timingSafeEqual(ab, bb);
}

export function createApp({
  env = process.env,
  fetchImpl = globalThis.fetch,
  now = () => Date.now(),
  quarantineStore,
  logger = log,
} = {}) {
  const config = loadShieldConfig(env);
  // Express resolves the client IP itself (TRUST_PROXY); never trust a raw header here.
  config.ip.clientIpHeader = 'none';
  const velocityTracker = createVelocityTracker({}, { windowSeconds: config.velocity.windowSeconds });
  const store =
    quarantineStore ||
    createQuarantineStore({
      filePath: path.resolve(ROOT_DIR, env.QUARANTINE_LOG_PATH || 'data/quarantine.jsonl'),
      retentionDays: Number(env.QUARANTINE_RETENTION_DAYS) || 30,
    });
  const adminToken = env.ADMIN_API_TOKEN;
  const adminEnabled = !isPlaceholderValue(adminToken) && String(adminToken).length >= 24;

  const app = express();
  app.disable('x-powered-by');
  app.set('trust proxy', parseTrustProxy(env.TRUST_PROXY));
  const bodyLimit = env.BODY_LIMIT || '64kb';

  app.use((req, res, next) => {
    res.set('cache-control', 'no-store');
    res.set('x-content-type-options', 'nosniff');
    const origin = req.get('origin');
    if (origin && req.path.startsWith('/v1/')) {
      const normalized = origin.replace(/\/+$/, '').toLowerCase();
      const allowed = config.browser.allowedOrigins.length ? config.browser.allowedOrigins.includes(normalized) : config.dryRun;
      if (allowed) {
        res.set('access-control-allow-origin', origin);
        res.set('vary', 'Origin');
        res.set('access-control-allow-methods', 'GET, POST, OPTIONS');
        res.set('access-control-allow-headers', 'content-type');
        res.set('access-control-max-age', '600');
      }
    }
    if (req.method === 'OPTIONS') return res.status(204).end();
    return next();
  });

  app.get('/healthz', (req, res) => {
    const { errors, warnings } = validateShieldConfig(config);
    res.json({ ok: errors.length === 0, dryRun: config.dryRun, sandboxMode: config.sandboxMode, asnProvider: config.ip.asnProvider, warnings: warnings.length, errors: errors.length });
  });

  app.get('/v1/form-token', (req, res) => {
    const secret = config.honeypot.tokenSecret;
    if (isPlaceholderValue(secret)) return res.json({ renderedAt: String(now()), token: null });
    return res.json(issueRenderToken(secret, now()));
  });

  app.post('/v1/submit', express.json({ limit: bodyLimit }), express.urlencoded({ extended: false, limit: bodyLimit }), async (req, res) => {
    const result = await processSubmission(
      { body: req.body || {}, headers: req.headers, socketIp: req.ip, query: req.query || {} },
      { config, velocityTracker, fetchImpl, now: now() },
    );
    if (result.ctx.quarantine?.record) {
      try {
        store.add(result.ctx.quarantine.record);
      } catch (err) {
        logger('error', 'quarantine_store_failed', { message: err.message });
      }
    }
    logger(result.ctx.status === 'error' ? 'error' : 'info', 'submission_processed', result.summary);
    res.status(result.response.httpStatus).json(result.response.body);
  });

  function requireAdmin(req, res, next) {
    if (!adminEnabled) return res.status(404).json({ error: 'not_found' });
    const header = req.get('authorization') || '';
    const token = header.startsWith('Bearer ') ? header.slice(7) : '';
    if (!safeEqual(token, adminToken)) return res.status(401).json({ error: 'unauthorized' });
    return next();
  }

  app.get('/admin/quarantine', requireAdmin, (req, res) => {
    const verdict = ['quarantine', 'block'].includes(req.query.verdict) ? req.query.verdict : null;
    res.json({ dryRun: config.dryRun, records: store.list({ limit: Number(req.query.limit) || 50, verdict }) });
  });

  app.post('/admin/quarantine/:id/release', requireAdmin, async (req, res) => {
    const record = store.get(req.params.id);
    if (!record) return res.status(404).json({ error: 'not_found' });
    if (record.releasedAt) return res.status(409).json({ error: 'already_released', releasedAt: record.releasedAt });
    if (!record.releasable) return res.status(422).json({ error: 'not_releasable', reason: 'honeypot submissions cannot be released' });
    try {
      const result = await deliverToHubSpot(record.release.hubspot, { config, fetchImpl });
      if (result.mode === 'delivered') store.markReleased(record.id, result);
      logger('info', 'quarantine_release', { id: record.id, mode: result.mode });
      return res.status(result.mode === 'rejected_by_hubspot' ? 502 : 200).json({ id: record.id, ...result });
    } catch (err) {
      return res.status(503).json({ id: record.id, error: err.code || 'release_failed' });
    }
  });

  app.use((req, res) => res.status(404).json({ error: 'not_found' }));
  // eslint-disable-next-line no-unused-vars
  app.use((err, req, res, next) => {
    const status = err.type === 'entity.too.large' ? 413 : err.type === 'entity.parse.failed' ? 400 : 500;
    if (status === 500) logger('error', 'unhandled_error', { message: err.message });
    res.status(status).json({ ok: false, status: status === 500 ? 'error' : 'bad_request' });
  });

  return { app, config, store, velocityTracker, adminEnabled };
}

export async function runSimulation({ env = process.env, fetchImpl = globalThis.fetch } = {}) {
  const fixtures = JSON.parse(fs.readFileSync(path.join(ROOT_DIR, 'fixtures', 'sample-submissions.json'), 'utf8'));
  const results = [];
  for (const fixture of fixtures) {
    const config = loadShieldConfig({ ...env, ...(fixture.env || {}), DRY_RUN: 'true' });
    config.ip.clientIpHeader = 'none';
    const velocityTracker = createVelocityTracker({}, { windowSeconds: config.velocity.windowSeconds });
    const t = Date.now();
    const body = { ...fixture.body, [config.honeypot.timestampField]: String(t - (fixture.secondsToFill ?? 20) * 1000) };
    let last;
    for (let i = 0; i < (fixture.repeat || 1); i += 1) {
      last = await processSubmission({ body, headers: fixture.headers, socketIp: fixture.ip, query: {} }, { config, velocityTracker, fetchImpl, now: t + i });
    }
    results.push({ name: fixture.name, expected: fixture.expectedVerdict, ...operatorSummary(last.ctx), client: last.response });
  }
  return results;
}

async function main(argv) {
  loadDotEnvFile();
  if (argv.includes('--simulate')) {
    const results = await runSimulation();
    for (const r of results) {
      const ok = r.verdict === r.expected ? '✓' : '✗';
      process.stdout.write(`\n${ok} ${r.name}\n  verdict=${r.verdict} (expected ${r.expected}) score=${r.score} status=${r.status}\n  signals: ${r.signals.join(', ') || 'none'}\n  hubspot=${r.hubspot?.mode || '-'} quarantineWebhook=${r.quarantineWebhook || '-'} client=${r.client.httpStatus} ${JSON.stringify(r.client.body)}\n`);
    }
    process.stdout.write('\nSimulation ran with DRY_RUN forced to true. Nothing was sent to HubSpot or any webhook.\n');
    process.exitCode = results.every((r) => r.verdict === r.expected) ? 0 : 1;
    return;
  }
  const { app, config, adminEnabled, store } = createApp();
  const { errors, warnings } = validateShieldConfig(config);
  warnings.forEach((warning) => log('warn', 'config_warning', { warning }));
  if (errors.length) {
    errors.forEach((error) => log('error', 'config_error', { error }));
    process.exitCode = 1;
    return;
  }
  const port = Number(process.env.PORT) || 3000;
  const server = app.listen(port, () =>
    log('info', 'server_started', { port, dryRun: config.dryRun, sandboxMode: config.sandboxMode, asnProvider: config.ip.asnProvider, adminEnabled, quarantineLog: path.relative(ROOT_DIR, store.filePath) }),
  );
  server.requestTimeout = 15000;
  const shutdown = () => server.close(() => process.exit(0));
  process.on('SIGTERM', shutdown);
  process.on('SIGINT', shutdown);
}

const invokedDirectly = process.argv[1] && import.meta.url === pathToFileURL(path.resolve(process.argv[1])).href;
if (invokedDirectly) {
  main(process.argv.slice(2)).catch((err) => {
    process.stderr.write(`${err.stack || err.message}\n`);
    process.exitCode = 1;
  });
}
