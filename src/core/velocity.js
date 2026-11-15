/**
 * Sliding-window velocity tracker over a plain object, so the same code works
 * in memory (Express), on n8n workflow static data, or on any JSON-backed store.
 *
 * backing shape: { "<key>": [timestampMs, ...] }
 */

export function createVelocityTracker(backing = {}, { windowSeconds = 600, maxKeys = 20000 } = {}) {
  const windowMs = windowSeconds * 1000;

  function pruneKey(key, now) {
    const list = Array.isArray(backing[key]) ? backing[key].filter((t) => now - t < windowMs) : [];
    if (list.length) backing[key] = list;
    else delete backing[key];
    return list;
  }

  function pruneAll(now) {
    const keys = Object.keys(backing);
    for (const key of keys) pruneKey(key, now);
    const remaining = Object.keys(backing);
    if (remaining.length > maxKeys) {
      remaining
        .sort((a, b) => Math.max(...backing[a]) - Math.max(...backing[b]))
        .slice(0, remaining.length - maxKeys)
        .forEach((key) => delete backing[key]);
    }
  }

  return {
    /** Records one hit per key and returns the in-window counts including this hit. */
    hit(keys, now = Date.now()) {
      pruneAll(now);
      const counts = {};
      for (const key of keys.filter(Boolean)) {
        const list = pruneKey(key, now);
        list.push(now);
        backing[key] = list.slice(-1000);
        counts[key] = list.length;
      }
      return counts;
    },
    count(key, now = Date.now()) {
      return pruneKey(key, now).length;
    },
    size: () => Object.keys(backing).length,
  };
}
