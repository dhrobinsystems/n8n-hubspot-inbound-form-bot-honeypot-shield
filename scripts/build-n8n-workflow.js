#!/usr/bin/env node
/**
 * Generates workflows/hubspot-honeypot-shield.json from src/core/.
 *
 * Each Code node embeds the same core modules the Express server imports
 * (imports and `export` keywords stripped) plus a few lines that run one stage.
 * The test suite rebuilds the workflow, fails if the committed JSON drifts, and
 * executes the Code nodes to compare their output with the Express mirror.
 */
import fs from 'node:fs';
import path from 'node:path';
import { fileURLToPath, pathToFileURL } from 'node:url';

const ROOT = path.resolve(path.dirname(fileURLToPath(import.meta.url)), '..');
export const OUTPUT_PATH = path.join(ROOT, 'workflows', 'hubspot-honeypot-shield.json');
export const CORE_MODULES = [
  'src/core/config.js',
  'src/core/disposableDomains.js',
  'src/core/textHeuristics.js',
  'src/core/ipReputation.js',
  'src/core/browserSignals.js',
  'src/core/velocity.js',
  'src/core/shield.js',
];
const PRELUDE_NAMES = ['env', 'config', 'n8nHelpers', 'n8nFetch', 'n8nSleep', 'staticData', 'velocityTracker', 'appendQuarantineLog', 'ctx', 'item', 'result', 'crypto'];
const TOP_LEVEL_DECL = /^(?:async\s+)?(?:function\*?|const|let|var|class)\s+([A-Za-z_$][\w$]*)/gm;

function stripModuleSyntax(source, file) {
  const out = source
    .replace(/^import\s[\s\S]*?from\s+['"][^'"]+['"];\s*$/gm, '')
    .replace(/^export\s+(?=(?:async\s+)?(?:function|const|let|class)\s)/gm, '');
  if (/^(?:import|export)\s/m.test(out)) throw new Error(`${file}: unsupported import/export syntax`);
  return out.replace(/\n{3,}/g, '\n\n').trim();
}

export function buildLibrarySource(root = ROOT) {
  const seen = new Map(PRELUDE_NAMES.map((n) => [n, 'n8n prelude']));
  const parts = [];
  for (const rel of CORE_MODULES) {
    const body = stripModuleSyntax(fs.readFileSync(path.join(root, rel), 'utf8'), rel);
    for (const m of body.matchAll(TOP_LEVEL_DECL)) {
      if (seen.has(m[1])) throw new Error(`Top-level name "${m[1]}" in ${rel} collides with ${seen.get(m[1])}`);
      seen.set(m[1], rel);
    }
    parts.push(`// ---- ${rel} ----\n${body}`);
  }
  return parts.join('\n\n');
}

const PRELUDE = `
const env = $env;
const config = loadShieldConfig(env);
const n8nHelpers = this.helpers;
const n8nSleep = (ms) => new Promise((resolve) => (typeof setTimeout === 'function' ? setTimeout(resolve, ms) : resolve()));
const n8nFetch = async (url, init = {}) => {
  const response = await n8nHelpers.httpRequest({
    url,
    method: init.method || 'GET',
    headers: init.headers || {},
    body: init.body,
    json: false,
    returnFullResponse: true,
    ignoreHttpStatusErrors: true,
    timeout: config.hubspot.timeoutMs,
  });
  const raw = response.body;
  const text = typeof raw === 'string' ? raw : Buffer.isBuffer(raw) ? raw.toString('utf8') : raw == null ? '' : JSON.stringify(raw);
  return {
    ok: response.statusCode >= 200 && response.statusCode < 300,
    status: response.statusCode,
    headers: { get: (name) => (response.headers || {})[String(name).toLowerCase()] ?? null },
    text: async () => text,
    json: async () => JSON.parse(text),
  };
};
const staticData = $getWorkflowStaticData('global');
if (!staticData.velocity) staticData.velocity = {};
if (!Array.isArray(staticData.quarantineLog)) staticData.quarantineLog = [];
const velocityTracker = createVelocityTracker(staticData.velocity, { windowSeconds: config.velocity.windowSeconds });
const appendQuarantineLog = (context) => {
  if (context.quarantine && context.quarantine.record) {
    staticData.quarantineLog.push(context.quarantine.record);
    if (staticData.quarantineLog.length > 200) staticData.quarantineLog.splice(0, staticData.quarantineLog.length - 200);
  }
};
`;

const CODE_NODES = [
  {
    name: 'Evaluate Risk Signals',
    body: `const item = $input.first();
const ctx = await evaluateStage(
  { body: item.json.body || {}, headers: item.json.headers || {}, socketIp: '', query: item.json.query || {} },
  { config, velocityTracker, fetchImpl: n8nFetch, now: Date.now() },
);
return [{ json: ctx }];`,
  },
  {
    name: 'Forward to HubSpot',
    body: `const ctx = await hubspotStage($input.first().json, { config, fetchImpl: n8nFetch, sleep: n8nSleep });
appendQuarantineLog(ctx);
return [{ json: ctx }];`,
  },
  {
    name: 'Quarantine & Log',
    body: `const ctx = await quarantineStage($input.first().json, { config, fetchImpl: n8nFetch });
appendQuarantineLog(ctx);
return [{ json: ctx }];`,
  },
  {
    name: 'Build Client Response',
    body: `const ctx = $input.first().json;
const result = clientResponse(ctx, config);
return [{ json: { httpStatus: result.httpStatus, body: result.body, summary: operatorSummary(ctx) } }];`,
  },
];

const IDS = {
  note: 'a7f3c2d1-0000-4e5f-8a9b-000000000001',
  webhook: 'a7f3c2d1-0000-4e5f-8a9b-000000000002',
  evaluate: 'a7f3c2d1-0000-4e5f-8a9b-000000000003',
  route: 'a7f3c2d1-0000-4e5f-8a9b-000000000004',
  hubspot: 'a7f3c2d1-0000-4e5f-8a9b-000000000005',
  quarantine: 'a7f3c2d1-0000-4e5f-8a9b-000000000006',
  response: 'a7f3c2d1-0000-4e5f-8a9b-000000000007',
  respond: 'a7f3c2d1-0000-4e5f-8a9b-000000000008',
  condition: 'a7f3c2d1-0000-4e5f-8a9b-000000000009',
  webhookId: 'a7f3c2d1-0000-4e5f-8a9b-0000000000aa',
};

const STICKY = `## HubSpot Inbound Form Bot & Honeypot Shield

Generated from src/core/ by scripts/build-n8n-workflow.js. Edit src/core/, then run \`npm run build:workflow\`.

**Safe by default:** DRY_RUN and SANDBOX_MODE stay true unless set to false. ASN lookups are off (ASN_LOOKUP_PROVIDER=none).

**n8n host settings**
- \`NODE_FUNCTION_ALLOW_BUILTIN=crypto\`
- \`N8N_BLOCK_ENV_ACCESS_IN_NODE=false\`
- \`CLIENT_IP_HEADER\` = the header your reverse proxy overwrites with the visitor IP (for example x-real-ip or cf-connecting-ip)

Velocity counters and the last 200 quarantine records live in workflow static data (production executions only).`;

export function buildWorkflow(root = ROOT) {
  const library = buildLibrarySource(root);
  const header = "// AUTO-GENERATED by scripts/build-n8n-workflow.js from src/core/. Edit src/core/, then run `npm run build:workflow`.\nconst crypto = require('crypto');";
  const code = (name) => `${header}\n\n${library}\n\n// ---- n8n stage runner ----${PRELUDE}\n${CODE_NODES.find((n) => n.name === name).body}\n`;
  const codeNode = (id, name, position) => ({ parameters: { jsCode: code(name) }, id, name, type: 'n8n-nodes-base.code', typeVersion: 2, position });
  const nodes = [
    { parameters: { content: STICKY, height: 380, width: 520 }, id: IDS.note, name: 'Read Me', type: 'n8n-nodes-base.stickyNote', typeVersion: 1, position: [-60, -440] },
    {
      parameters: { httpMethod: 'POST', path: 'hubspot-form-shield', responseMode: 'responseNode', options: {} },
      id: IDS.webhook,
      name: 'Form Submission Webhook',
      type: 'n8n-nodes-base.webhook',
      typeVersion: 2,
      position: [0, 0],
      webhookId: IDS.webhookId,
    },
    codeNode(IDS.evaluate, 'Evaluate Risk Signals', [240, 0]),
    {
      parameters: {
        conditions: {
          options: { caseSensitive: true, leftValue: '', typeValidation: 'strict' },
          conditions: [
            {
              id: IDS.condition,
              leftValue: "={{ $json.decision ? $json.decision.verdict : 'error' }}",
              rightValue: 'allow',
              operator: { type: 'string', operation: 'equals' },
            },
          ],
          combinator: 'and',
        },
        options: {},
      },
      id: IDS.route,
      name: 'Verdict is Allow?',
      type: 'n8n-nodes-base.if',
      typeVersion: 2,
      position: [480, 0],
    },
    codeNode(IDS.hubspot, 'Forward to HubSpot', [720, -120]),
    codeNode(IDS.quarantine, 'Quarantine & Log', [720, 120]),
    codeNode(IDS.response, 'Build Client Response', [960, 0]),
    {
      parameters: {
        respondWith: 'json',
        responseBody: '={{ JSON.stringify($json.body) }}',
        options: { responseCode: '={{ $json.httpStatus }}' },
      },
      id: IDS.respond,
      name: 'Respond to Browser',
      type: 'n8n-nodes-base.respondToWebhook',
      typeVersion: 1.1,
      position: [1200, 0],
    },
  ];
  const link = (node) => ({ node, type: 'main', index: 0 });
  const connections = {
    'Form Submission Webhook': { main: [[link('Evaluate Risk Signals')]] },
    'Evaluate Risk Signals': { main: [[link('Verdict is Allow?')]] },
    'Verdict is Allow?': { main: [[link('Forward to HubSpot')], [link('Quarantine & Log')]] },
    'Forward to HubSpot': { main: [[link('Build Client Response')]] },
    'Quarantine & Log': { main: [[link('Build Client Response')]] },
    'Build Client Response': { main: [[link('Respond to Browser')]] },
  };
  return {
    name: 'HubSpot Inbound Form Bot & Honeypot Shield',
    nodes,
    connections,
    active: false,
    settings: { executionOrder: 'v1', saveDataSuccessExecution: 'none', saveDataErrorExecution: 'all', saveManualExecutions: false },
    pinData: {},
    meta: { templateCredsSetupCompleted: true },
    tags: [],
  };
}

export function serializeWorkflow(workflow) {
  return `${JSON.stringify(workflow, null, 2)}\n`;
}

const invokedDirectly = process.argv[1] && import.meta.url === pathToFileURL(path.resolve(process.argv[1])).href;
if (invokedDirectly) {
  const json = serializeWorkflow(buildWorkflow());
  fs.writeFileSync(OUTPUT_PATH, json);
  process.stdout.write(`Wrote ${path.relative(ROOT, OUTPUT_PATH)} (${(json.length / 1024).toFixed(1)} KiB)\n`);
}
