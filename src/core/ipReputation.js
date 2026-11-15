/**
 * Client IP resolution, CIDR allow/block lists and ASN reputation screening.
 *
 * ASN data sources (ASN_LOOKUP_PROVIDER):
 *   none   (default) no lookup, no outbound call; ASN checks are skipped.
 *   header ASN supplied by a trusted edge (CDN / load balancer) in a request header.
 *   ipinfo GET https://ipinfo.io/<ip>?token=... (outbound call per submission).
 *
 * A hosting/datacenter ASN is a risk signal, not proof of abuse: VPN users and
 * corporate egress proxies also come from these networks, which is why the
 * default is to add points (quarantine-leaning) rather than block outright.
 */

export const DATACENTER_ASNS = {
  16509: 'Amazon AWS', 14618: 'Amazon AWS', 8987: 'Amazon AWS', 15169: 'Google', 396982: 'Google Cloud',
  19527: 'Google', 8075: 'Microsoft Azure', 14061: 'DigitalOcean', 16276: 'OVH', 24940: 'Hetzner',
  213230: 'Hetzner Cloud', 63949: 'Akamai Linode', 20473: 'Vultr (Choopa)', 51167: 'Contabo', 45102: 'Alibaba Cloud',
  37963: 'Alibaba Cloud', 132203: 'Tencent Cloud', 45090: 'Tencent Cloud', 31898: 'Oracle Cloud', 12876: 'Scaleway',
  60781: 'Leaseweb', 28753: 'Leaseweb', 9009: 'M247', 62240: 'Clouvider', 36352: 'ColoCrossing',
  53667: 'FranTech / BuyVM', 46606: 'Unified Layer', 26496: 'GoDaddy', 398101: 'GoDaddy', 40021: 'Contabo US',
  197540: 'netcup', 212238: 'Datacamp', 60068: 'Datacamp (CDN77)', 136907: 'Huawei Cloud', 55990: 'Huawei Cloud',
  3223: 'Voxility', 49981: 'WorldStream', 206092: 'IPXO',
};

export function firstForwardedIp(value) {
  if (!value) return '';
  const first = String(Array.isArray(value) ? value[0] : value).split(',')[0].trim();
  return first.replace(/^\[|\]$/g, '').replace(/^::ffff:/i, '');
}

export function parseIpv4(ip) {
  const m = String(ip ?? '').match(/^(\d{1,3})\.(\d{1,3})\.(\d{1,3})\.(\d{1,3})$/);
  if (!m) return null;
  const octets = m.slice(1).map(Number);
  if (octets.some((o) => o > 255)) return null;
  return ((octets[0] << 24) >>> 0) + (octets[1] << 16) + (octets[2] << 8) + octets[3];
}

export function isIpv6(ip) {
  return /^[0-9a-f:]+$/i.test(String(ip ?? '')) && String(ip).includes(':');
}

export function isPrivateOrReservedIp(ip) {
  const n = parseIpv4(ip);
  if (n !== null) {
    const inRange = (base, bits) => (n >>> (32 - bits)) === (parseIpv4(base) >>> (32 - bits));
    return (
      inRange('10.0.0.0', 8) || inRange('172.16.0.0', 12) || inRange('192.168.0.0', 16) || inRange('127.0.0.0', 8) ||
      inRange('169.254.0.0', 16) || inRange('100.64.0.0', 10) || inRange('0.0.0.0', 8) || inRange('192.0.2.0', 24) ||
      inRange('198.51.100.0', 24) || inRange('203.0.113.0', 24) || inRange('224.0.0.0', 4)
    );
  }
  const v6 = String(ip ?? '').toLowerCase();
  return v6 === '::1' || v6.startsWith('fc') || v6.startsWith('fd') || v6.startsWith('fe80') || v6.startsWith('2001:db8');
}

/** IPv4 CIDR (a.b.c.d/n) or exact IPv4/IPv6 address match. */
export function ipMatchesRule(ip, rule) {
  const [base, bitsText] = String(rule).trim().split('/');
  const ipNum = parseIpv4(ip);
  const baseNum = parseIpv4(base);
  if (ipNum !== null && baseNum !== null) {
    const bits = bitsText === undefined ? 32 : Number(bitsText);
    if (!Number.isInteger(bits) || bits < 0 || bits > 32) return false;
    if (bits === 0) return true;
    return (ipNum >>> (32 - bits)) === (baseNum >>> (32 - bits));
  }
  return bitsText === undefined && String(ip).toLowerCase() === String(base).toLowerCase();
}

export function parseAsnValue(value) {
  if (value === undefined || value === null || value === '') return null;
  const m = String(value).match(/(?:AS)?(\d{1,10})/i);
  return m ? Number(m[1]) : null;
}

/** Returns { asn, org, source }; never throws (lookup failures become source "error"). */
export async function lookupAsn({ ip, headers = {}, ipConfig, fetchImpl }) {
  if (ipConfig.asnProvider === 'header') {
    const lower = Object.fromEntries(Object.entries(headers || {}).map(([k, v]) => [k.toLowerCase(), v]));
    const asn = parseAsnValue(lower[ipConfig.asnHeader]);
    return { asn, org: lower[ipConfig.asnOrgHeader] ? String(lower[ipConfig.asnOrgHeader]).slice(0, 120) : null, source: asn ? 'header' : 'header_missing' };
  }
  if (ipConfig.asnProvider === 'ipinfo' && ip && !isPrivateOrReservedIp(ip)) {
    try {
      const controller = typeof AbortController === 'function' ? new AbortController() : null;
      const timer = controller ? setTimeout(() => controller.abort(), ipConfig.ipinfoTimeoutMs) : null;
      const response = await fetchImpl(`https://ipinfo.io/${encodeURIComponent(ip)}/json?token=${encodeURIComponent(ipConfig.ipinfoToken)}`, {
        method: 'GET',
        headers: { accept: 'application/json' },
        ...(controller ? { signal: controller.signal } : {}),
      });
      if (timer) clearTimeout(timer);
      if (!response.ok) return { asn: null, org: null, source: 'error' };
      const body = JSON.parse(await response.text());
      const asn = parseAsnValue(body?.asn?.asn || body?.org);
      const org = String(body?.asn?.name || body?.org || '').replace(/^AS\d+\s*/i, '').slice(0, 120) || null;
      return { asn, org, source: 'ipinfo', privacy: body?.privacy || null };
    } catch {
      return { asn: null, org: null, source: 'error' };
    }
  }
  return { asn: null, org: null, source: 'none' };
}

export function evaluateIpSignals({ ip, asnInfo, ipConfig }) {
  const signals = [];
  let allowlisted = false;
  if (!ip) {
    signals.push({ id: 'ip_unresolved', points: 10, detail: 'no client IP could be determined' });
    return { signals, allowlisted };
  }
  if (ipConfig.allowlistCidrs.some((rule) => ipMatchesRule(ip, rule))) {
    allowlisted = true;
    return { signals, allowlisted };
  }
  if (ipConfig.blocklistCidrs.some((rule) => ipMatchesRule(ip, rule))) {
    signals.push({ id: 'ip_blocklisted', points: 100, hard: 'block', detail: 'IP matches IP_BLOCKLIST_CIDRS' });
  }
  if (isPrivateOrReservedIp(ip)) {
    signals.push({ id: 'ip_private_or_reserved', points: 10, detail: 'private/reserved address: check proxy and CLIENT_IP_HEADER settings' });
  }
  const asn = asnInfo?.asn ?? null;
  if (asn !== null) {
    const extra = new Set(ipConfig.extraDatacenterAsns);
    const known = DATACENTER_ASNS[asn];
    if (known || extra.has(asn)) {
      signals.push({
        id: 'asn_datacenter',
        points: 35,
        detail: `AS${asn} ${known || asnInfo.org || 'listed in DATACENTER_ASNS_EXTRA'}`,
      });
    }
  }
  const privacy = asnInfo?.privacy;
  if (privacy && typeof privacy === 'object') {
    if (privacy.tor) signals.push({ id: 'ip_tor_exit', points: 40, detail: 'Tor exit node (ipinfo privacy data)' });
    else if (privacy.vpn || privacy.proxy) signals.push({ id: 'ip_anonymizer', points: 20, detail: 'VPN or proxy (ipinfo privacy data)' });
    if (privacy.hosting && !signals.some((s) => s.id === 'asn_datacenter')) {
      signals.push({ id: 'ip_hosting', points: 30, detail: 'hosting provider (ipinfo privacy data)' });
    }
  }
  if (asnInfo?.source === 'header_missing') {
    signals.push({ id: 'asn_header_missing', points: 5, detail: 'ASN header expected from the edge but absent' });
  }
  return { signals, allowlisted };
}
