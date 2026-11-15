/**
 * Gibberish, entropy and spam heuristics for free-text form fields.
 *
 * Fairness rule: the keyboard-smash, vowel and consonant-run checks only run on
 * text that is mostly Latin script. Names written in other scripts are never
 * penalised for "looking unusual" to an English-centric heuristic.
 */

const KEYBOARD_ROWS = ['qwertyuiop', 'asdfghjkl', 'zxcvbnm', '1234567890', 'qwertzuiop', 'azertyuiop', 'yxcvbnm'];
const FIELD_POINT_CAP = 45;

const SPAM_PHRASES = [
  { re: /\bseo (?:services?|agency|expert)\b/i, points: 25, id: 'seo_pitch' },
  { re: /\b(?:rank|ranking) (?:your|ur) (?:website|site)\b|\bfirst page of google\b/i, points: 25, id: 'seo_pitch' },
  { re: /\b(?:guest posts?|backlinks?|link building|domain authority)\b/i, points: 25, id: 'link_building' },
  { re: /\b(?:bitcoin|crypto(?:currency)?|forex|binary options?) (?:investment|trading|profit|opportunit)/i, points: 30, id: 'crypto_pitch' },
  { re: /\b(?:casino|viagra|cialis|payday loan|loan offer)\b/i, points: 35, id: 'classic_spam' },
  { re: /\b(?:increase|boost) (?:your )?(?:website )?traffic\b|\bweb ?design services\b|\bapp development services\b/i, points: 20, id: 'agency_pitch' },
  { re: /\bas an ai(?: language model)?\b|\bregenerate response\b|\bi cannot fulfill (?:this|that) request\b/i, points: 40, id: 'llm_artifact' },
  { re: /\[(?:your|recipient'?s?|company) name\]|\{\{?\s*(?:first_?name|company|name)\s*\}?\}|<(?:your|first) name>/i, points: 35, id: 'unfilled_template' },
  { re: /\bdear (?:sir|madam|sir\/madam|website owner)\b/i, points: 10, id: 'generic_salutation' },
];

export function shannonEntropy(text) {
  const s = String(text ?? '');
  if (!s.length) return 0;
  const counts = new Map();
  for (const ch of s) counts.set(ch, (counts.get(ch) || 0) + 1);
  let entropy = 0;
  const length = [...s].length;
  for (const count of counts.values()) {
    const p = count / length;
    entropy -= p * Math.log2(p);
  }
  return Math.round(entropy * 1000) / 1000;
}

export function isMostlyLatin(text) {
  const letters = String(text ?? '').match(/\p{L}/gu) || [];
  if (!letters.length) return false;
  const latin = letters.filter((ch) => /[A-Za-zÀ-ɏ]/.test(ch)).length;
  return latin / letters.length >= 0.8;
}

function longestKeyboardSequence(text) {
  const s = String(text ?? '').toLowerCase().replace(/[^a-z0-9]/g, '');
  let best = 0;
  for (const row of KEYBOARD_ROWS) {
    const reversed = [...row].reverse().join('');
    for (const line of [row, reversed]) {
      for (let len = Math.min(line.length, s.length); len >= 4 && len > best; len -= 1) {
        let found = false;
        for (let i = 0; i + len <= line.length; i += 1) {
          if (s.includes(line.slice(i, i + len))) {
            found = true;
            break;
          }
        }
        if (found) {
          best = len;
          break;
        }
      }
    }
  }
  return best;
}

export function countUrls(text) {
  return (String(text ?? '').match(/\bhttps?:\/\/[^\s<>"]+|\bwww\.[^\s<>"]+/gi) || []).length;
}

function signalOf(id, points, detail) {
  return { id, points, detail };
}

/** Scores one field. kind: "name" | "company" | "message" | "text". */
export function analyzeTextField(value, kind = 'text', { maxUrls = 2 } = {}) {
  const text = String(value ?? '').trim();
  const signals = [];
  if (!text) return { signals, entropy: 0, points: 0 };
  const entropy = shannonEntropy(text);
  const latin = isMostlyLatin(text);
  const compact = text.replace(/\s+/g, '');
  const letters = (text.match(/\p{L}/gu) || []).join('');

  if (latin && letters.length >= 4) {
    if (/[bcdfghjklmnpqrstvwxz]{5,}/i.test(letters)) signals.push(signalOf('consonant_run', 25, 'five or more consonants in a row'));
    const vowels = (letters.match(/[aeiouyàáâãäåèéêëìíîïòóôõöùúûüý]/gi) || []).length;
    if (letters.length >= 6 && vowels / letters.length < 0.15) {
      signals.push(signalOf('low_vowel_ratio', 20, `vowel ratio ${(vowels / letters.length).toFixed(2)}`));
    }
    const keyboard = longestKeyboardSequence(text);
    if (keyboard >= 4) signals.push(signalOf('keyboard_sequence', 30, `keyboard row sequence of ${keyboard} characters`));
  }
  if (/(.)\1{3,}/u.test(compact)) signals.push(signalOf('repeated_characters', 20, 'same character four or more times in a row'));
  if (kind === 'name' && /\d/.test(text)) signals.push(signalOf('digits_in_name', 15, 'digits in a name field'));
  if (kind === 'name' && text.length > 60) signals.push(signalOf('overlong_name', 15, `${text.length} characters`));
  if (kind === 'name' && countUrls(text) > 0) signals.push(signalOf('url_in_name', 40, 'URL inside a name field'));
  if (compact.length >= 12 && !/\s/.test(text) && entropy >= 3.7 && kind !== 'message') {
    signals.push(signalOf('random_token', 30, `entropy ${entropy} bits/char with no spaces`));
  }
  if (kind === 'message') {
    if (text.length >= 20 && entropy < 2.5) signals.push(signalOf('low_entropy_message', 20, `entropy ${entropy} bits/char`));
    const words = text.toLowerCase().match(/\p{L}+/gu) || [];
    if (words.length >= 6 && new Set(words).size / words.length < 0.3) {
      signals.push(signalOf('repetitive_words', 15, 'few distinct words'));
    }
    const urls = countUrls(text);
    if (urls > maxUrls) signals.push(signalOf('too_many_urls', 20, `${urls} URLs`));
    if (/\[url=|<a\s+href|\[link=/i.test(text)) signals.push(signalOf('markup_links', 30, 'BBCode or HTML links'));
    const upper = (letters.match(/\p{Lu}/gu) || []).length;
    if (letters.length > 20 && upper / letters.length > 0.7) signals.push(signalOf('shouting', 10, 'mostly capital letters'));
    if (text.length > 5000) signals.push(signalOf('overlong_message', 10, `${text.length} characters`));
    for (const phrase of SPAM_PHRASES) {
      if (phrase.re.test(text) && !signals.some((s) => s.id === phrase.id)) {
        signals.push(signalOf(phrase.id, phrase.points, 'matched spam phrase pattern'));
      }
    }
  }
  const points = Math.min(FIELD_POINT_CAP, signals.reduce((sum, s) => sum + s.points, 0));
  return { signals, entropy, points };
}
