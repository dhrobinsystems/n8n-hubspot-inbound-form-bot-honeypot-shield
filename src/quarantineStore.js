/**
 * Append-only JSONL review log for quarantined and blocked submissions (Node.js runtime).
 *
 * Each line is an event: { event: "quarantined", record } or
 * { event: "released", id, at, result }. Records older than the retention period
 * are dropped when the store opens. The file is created with mode 0600.
 */
import fs from 'node:fs';
import path from 'node:path';

export function createQuarantineStore({ filePath, retentionDays = 30, now = () => Date.now() }) {
  const records = new Map();
  fs.mkdirSync(path.dirname(filePath), { recursive: true });
  if (fs.existsSync(filePath)) {
    const cutoff = now() - retentionDays * 24 * 3600 * 1000;
    const kept = [];
    for (const line of fs.readFileSync(filePath, 'utf8').split('\n')) {
      if (!line.trim()) continue;
      let event;
      try {
        event = JSON.parse(line);
      } catch {
        continue;
      }
      if (event.event === 'quarantined' && event.record?.id) {
        if (Date.parse(event.record.receivedAt) < cutoff) continue;
        records.set(event.record.id, { ...event.record, releasedAt: null, releaseResult: null });
        kept.push(line);
      } else if (event.event === 'released' && records.has(event.id)) {
        Object.assign(records.get(event.id), { releasedAt: event.at, releaseResult: event.result });
        kept.push(line);
      }
    }
    fs.writeFileSync(filePath, kept.length ? `${kept.join('\n')}\n` : '', { mode: 0o600 });
  }

  function append(event) {
    fs.appendFileSync(filePath, `${JSON.stringify(event)}\n`, { mode: 0o600 });
  }

  return {
    filePath,
    add(record) {
      records.set(record.id, { ...record, releasedAt: null, releaseResult: null });
      append({ event: 'quarantined', record });
    },
    get(id) {
      return records.get(id) || null;
    },
    list({ limit = 50, verdict = null } = {}) {
      return [...records.values()]
        .filter((r) => !verdict || r.verdict === verdict)
        .sort((a, b) => Date.parse(b.receivedAt) - Date.parse(a.receivedAt))
        .slice(0, Math.min(Math.max(1, limit), 500))
        .map(({ release, ...rest }) => rest);
    },
    markReleased(id, result) {
      const record = records.get(id);
      if (!record) return null;
      const at = new Date(now()).toISOString();
      Object.assign(record, { releasedAt: at, releaseResult: result });
      append({ event: 'released', id, at, result });
      return record;
    },
    size: () => records.size,
  };
}
