/**
 * Disposable / temporary email detection and email syntax checks.
 *
 * The bundled list covers widely used throwaway providers and their common
 * alias domains. It will never be complete: extend it at runtime with
 * DISPOSABLE_DOMAINS_EXTRA, or replace the list with a maintained source as
 * part of your deployment. Subdomains of a listed domain are also matched.
 */

export const DISPOSABLE_EMAIL_DOMAINS = [
  '0-mail.com', '0815.ru', '0clickemail.com', '10minutemail.com', '10minutemail.net', '10minutemail.co.uk',
  '10minutesmail.com', '20minutemail.com', '20minutemail.it', '33mail.com', 'anonbox.net', 'anonymbox.com',
  'antispam.de', 'armyspy.com', 'binkmail.com', 'bobmail.info', 'bccto.me', 'burnermail.io', 'byom.de',
  'chacuo.net', 'cock.li', 'cuvox.de', 'dayrep.com', 'deadaddress.com', 'despam.it', 'devnullmail.com',
  'discard.email', 'discardmail.com', 'discardmail.de', 'dispostable.com', 'dodgit.com', 'dropmail.me',
  'e4ward.com', 'einrot.com', 'emailondeck.com', 'emailfake.com', 'emailsensei.com', 'emailtemporanea.net',
  'emltmp.com', 'fakeinbox.com', 'fakemail.net', 'fakemailgenerator.com', 'fastacura.com', 'fleckens.hu',
  'filzmail.com', 'getairmail.com', 'getnada.com', 'gishpuppy.com', 'grr.la', 'guerrillamail.biz',
  'guerrillamail.com', 'guerrillamail.de', 'guerrillamail.info', 'guerrillamail.net', 'guerrillamail.org',
  'guerrillamailblock.com', 'gustr.com', 'harakirimail.com', 'hidemail.de', 'hmamail.com', 'inboxalias.com',
  'inboxbear.com', 'incognitomail.org', 'instant-mail.de', 'jetable.org', 'jourrapide.com', 'kasmail.com',
  'killmail.net', 'kurzepost.de', 'letthemeatspam.com', 'lhsdv.com', 'linshiyouxiang.net', 'lroid.com',
  'mail-temp.com', 'mail.tm', 'mail7.io', 'mailcatch.com', 'maildrop.cc', 'mailexpire.com', 'mailforspam.com',
  'mailinator.com', 'mailinator.net', 'mailinator.org', 'mailinator2.com', 'mailmetrash.com', 'mailnesia.com',
  'mailnull.com', 'mailpoof.com', 'mailsac.com', 'mailtemp.info', 'mailtothis.com', 'meltmail.com',
  'mintemail.com', 'mohmal.com', 'moakt.com', 'mt2015.com', 'mvrht.com', 'mytemp.email', 'mytrashmail.com',
  'nada.email', 'neverbox.com', 'no-spam.ws', 'nospam.ze.tc', 'nospamfor.us', 'nowmymail.com', 'objectmail.com',
  'one-time.email', 'onewaymail.com', 'owlymail.com', 'pokemail.net', 'proxymail.eu', 'rcpt.at',
  'rhyta.com', 'rmqkr.net', 'safetymail.info', 'sharklasers.com', 'shieldemail.com', 'sneakemail.com',
  'snkmail.com', 'sofimail.com', 'spam4.me', 'spamavert.com', 'spambog.com', 'spambox.us', 'spamex.com',
  'spamfree24.org', 'spamgourmet.com', 'spamhole.com', 'spaml.de', 'spammotel.com', 'spamspot.com',
  'spamthis.co.uk', 'superrito.com', 'tafmail.com', 'teleworm.us', 'temp-mail.io', 'temp-mail.org',
  'temp-mail.ru', 'tempail.com', 'tempemail.co', 'tempemail.net', 'tempinbox.com', 'tempmail.dev',
  'tempmail.net', 'tempmail.plus', 'tempmailaddress.com', 'tempmailo.com', 'tempmail.email', 'tempr.email',
  'tempsky.com', 'thankyou2010.com', 'throwam.com', 'throwawayemailaddress.com', 'throwawaymail.com',
  'tmail.ws', 'tmailinator.com', 'tmpmail.net', 'tmpmail.org', 'trash-mail.com', 'trash-mail.de',
  'trash2009.com', 'trashmail.at', 'trashmail.com', 'trashmail.de', 'trashmail.io', 'trashmail.me',
  'trashmail.net', 'trashmailer.com', 'trashymail.com', 'trbvm.com', 'tyldd.com', 'uggsrock.com',
  'veryrealemail.com', 'vomoto.com', 'wegwerfmail.de', 'wegwerfmail.net', 'wegwerfmail.org', 'yopmail.com',
  'yopmail.fr', 'yopmail.net', 'zetmail.com', 'zoemail.org',
];

export const FREE_MAIL_DOMAINS = [
  'gmail.com', 'googlemail.com', 'outlook.com', 'hotmail.com', 'live.com', 'msn.com', 'yahoo.com', 'ymail.com',
  'icloud.com', 'me.com', 'mac.com', 'aol.com', 'proton.me', 'protonmail.com', 'gmx.com', 'gmx.de', 'gmx.net',
  'web.de', 'zoho.com', 'yandex.com', 'yandex.ru', 'mail.com', 'mail.ru', 'qq.com', '163.com', '126.com',
];

const DISPOSABLE_SET = new Set(DISPOSABLE_EMAIL_DOMAINS);
const FREE_MAIL_SET = new Set(FREE_MAIL_DOMAINS);
const EMAIL_SYNTAX_RE = /^[A-Za-z0-9.!#$%&'*+/=?^_`{|}~-]{1,64}@(?=.{4,253}$)(?:[A-Za-z0-9](?:[A-Za-z0-9-]{0,61}[A-Za-z0-9])?\.)+[A-Za-z]{2,63}$/;

export function normalizeEmailAddress(value) {
  if (value === undefined || value === null) return '';
  return String(value).trim().toLowerCase();
}

export function isValidEmailSyntax(email) {
  const e = normalizeEmailAddress(email);
  if (!EMAIL_SYNTAX_RE.test(e)) return false;
  const local = e.split('@')[0];
  return !local.startsWith('.') && !local.endsWith('.') && !local.includes('..');
}

export function emailDomainOf(email) {
  const e = normalizeEmailAddress(email);
  const at = e.lastIndexOf('@');
  return at > 0 ? e.slice(at + 1) : '';
}

function domainOrParentInSet(domain, set) {
  const parts = String(domain || '').toLowerCase().split('.');
  for (let i = 0; i < parts.length - 1; i += 1) {
    if (set.has(parts.slice(i).join('.'))) return parts.slice(i).join('.');
  }
  return null;
}

export function matchDisposableDomain(domain, extraDomains = []) {
  const direct = domainOrParentInSet(domain, DISPOSABLE_SET);
  if (direct) return direct;
  return extraDomains.length ? domainOrParentInSet(domain, new Set(extraDomains)) : null;
}

export function isFreeMailDomain(domain) {
  return FREE_MAIL_SET.has(String(domain || '').toLowerCase());
}

/** Plus-addressing and dot tricks collapse to one mailbox for velocity counting. */
export function canonicalMailbox(email) {
  const e = normalizeEmailAddress(email);
  const domain = emailDomainOf(e);
  if (!domain) return e;
  let local = e.slice(0, e.lastIndexOf('@')).split('+')[0];
  if (domain === 'gmail.com' || domain === 'googlemail.com') local = local.replace(/\./g, '');
  return `${local}@${domain}`;
}
