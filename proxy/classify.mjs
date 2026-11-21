// Address and host-name classifier for the egress proxy. Pure: no DNS, no I/O, no logging.
// Ranges follow the IANA special-purpose registries (RFC 6890 and updates): RFC 1122/1918/6598/3927/5737/6890/2544/3068/3849/4193/4291/4380/6052/6666.
// Range classes are the closed vocabulary of llm_url_scan/logs.py RANGE_CLASSES.

import { isIPv6 as net_isIPv6 } from 'node:net';

export const NAME_SUFFIXES = ['localhost', 'local', 'localdomain', 'lan', 'home', 'corp', 'intranet', 'private', 'internal', 'test', 'invalid',
  'home.arpa', 'svc', 'cluster.local'];

const V4_RANGES = [
  ['0.0.0.0/8', 'loopback_or_unspecified'],
  ['127.0.0.0/8', 'loopback_or_unspecified'],
  ['10.0.0.0/8', 'private'],
  ['100.64.0.0/10', 'private'],
  ['172.16.0.0/12', 'private'],
  ['192.168.0.0/16', 'private'],
  ['169.254.0.0/16', 'link_local_or_metadata'],
  ['192.0.0.0/24', 'reserved_or_doc'],
  ['192.0.2.0/24', 'reserved_or_doc'],
  ['192.88.99.0/24', 'reserved_or_doc'],
  ['198.18.0.0/15', 'reserved_or_doc'],
  ['198.51.100.0/24', 'reserved_or_doc'],
  ['203.0.113.0/24', 'reserved_or_doc'],
  ['224.0.0.0/3', 'reserved_or_doc'], // multicast 224/4 and reserved 240/4 (incl. the broadcast address)
];
const V6_RANGES = [
  ['::/128', 'loopback_or_unspecified'],
  ['::1/128', 'loopback_or_unspecified'],
  ['fd00:ec2::/32', 'link_local_or_metadata'], // cloud metadata over IPv6
  ['fc00::/7', 'private'],
  ['fe80::/10', 'link_local_or_metadata'],
  ['ff00::/8', 'reserved_or_doc'],
  ['2001:db8::/32', 'reserved_or_doc'],
  ['3fff::/20', 'reserved_or_doc'],
];
// IPv6 ranges that embed an IPv4 address in the low 32 bits: the class is that of the embedded address, else v6_other. All are blocked.
const V6_EMBEDDING = ['::ffff:0:0/96', '::/96', '64:ff9b::/96'];
// Blocked IPv6 without a better class: 2001::/23 (protocol assignments, Teredo, benchmarking, ORCHID), 6to4, NAT64 local-use. Everything outside 2000::/3 too.
const V6_OTHER = ['2001::/23', '2002::/16', '64:ff9b:1::/48'];
const V6_GLOBAL = '2000::/3';

const V4_RE = /^(0|[1-9]\d{0,2})\.(0|[1-9]\d{0,2})\.(0|[1-9]\d{0,2})\.(0|[1-9]\d{0,2})$/;
const NUMERIC_RE = /^(0x[0-9a-f]+|\d+)(\.(0x[0-9a-f]+|\d+))*$/i;
const LABEL_RE = /^[a-z0-9_]([a-z0-9_-]{0,61}[a-z0-9_])?$/;

/** Strict dotted-quad -> unsigned integer, or null (leading zeros, short forms and out-of-range parts are not canonical). */
export function parseV4(s) {
  const m = V4_RE.exec(s);
  if (!m) return null;
  let n = 0;
  for (let i = 1; i <= 4; i++) {
    const p = Number(m[i]);
    if (p > 255) return null;
    n = n * 256 + p;
  }
  return n;
}

/** IPv6 text (no brackets, no zone id) -> BigInt, or null. Accepts a dotted IPv4 tail. */
export function parseV6(s) {
  if (typeof s !== 'string' || s.includes('%') || !net_isIPv6(s)) return null;
  const tail = /^(.*:)(\d+\.\d+\.\d+\.\d+)$/.exec(s);
  if (tail) {
    const v = parseV4(tail[2]);
    if (v === null) return null;
    s = tail[1] + (v >>> 16).toString(16) + ':' + (v & 0xffff).toString(16);
  }
  const halves = s.split('::');
  const head = halves[0] ? halves[0].split(':') : [];
  const rest = halves.length === 2 && halves[1] ? halves[1].split(':') : [];
  const groups = halves.length === 2 ? [...head, ...Array(8 - head.length - rest.length).fill('0'), ...rest] : head;
  if (groups.length !== 8) return null;
  let n = 0n;
  for (const g of groups) n = (n << 16n) | BigInt(parseInt(g, 16));
  return n;
}

function cidr(text) {
  const slash = text.indexOf('/');
  if (slash < 1 || !/^\d{1,3}$/.test(text.slice(slash + 1))) throw new Error('cidr');
  const addr = text.slice(0, slash);
  const len = Number(text.slice(slash + 1));
  const v4 = parseV4(addr);
  if (v4 !== null) {
    if (len > 32) throw new Error('cidr');
    return { fam: 4, len, base: BigInt(v4) >> BigInt(32 - len) };
  }
  const v6 = parseV6(addr);
  if (v6 === null || len > 128) throw new Error('cidr');
  return { fam: 6, len, base: v6 >> BigInt(128 - len) };
}

const within = (fam, n, c) => c.fam === fam && (n >> BigInt((fam === 4 ? 32 : 128) - c.len)) === c.base;
const table = (rows) => rows.map(([t, cls]) => ({ ...cidr(t), cls }));
const T4 = table(V4_RANGES);
const T6 = table(V6_RANGES);
const EMBED = V6_EMBEDDING.map(cidr);
const OTHER6 = V6_OTHER.map(cidr);
const GLOBAL6 = cidr(V6_GLOBAL);

/** Comma list of CIDRs, or the exact word `none`, -> array for classifyAddress. Throws (no detail) when any entry is invalid. */
export function parseCidrs(text) {
  if (text === 'none') return [];
  return text.split(',').map((s) => s.trim()).filter(Boolean).map(cidr);
}

const v4Class = (n) => T4.find((r) => within(4, BigInt(n), r))?.cls ?? null;

/**
 * IP text (v4 or v6, no brackets) -> the range class when blocked, else null (public). Text that is not an address is blocked as v6_other.
 * Built-in ranges win over the operator's extra CIDRs, which report as own_or_extra.
 */
export function classifyAddress(text, extras = []) {
  const v4 = parseV4(text);
  if (v4 !== null) return v4Class(v4) ?? (extras.some((c) => within(4, BigInt(v4), c)) ? 'own_or_extra' : null);
  const n = parseV6(text);
  if (n === null) return 'v6_other';
  const hit = T6.find((r) => within(6, n, r));
  if (hit) return hit.cls;
  if (EMBED.some((c) => within(6, n, c))) return v4Class(Number(n & 0xffffffffn)) ?? 'v6_other';
  if (!within(6, n, GLOBAL6) || OTHER6.some((c) => within(6, n, c))) return 'v6_other';
  return extras.some((c) => within(6, n, c)) ? 'own_or_extra' : null;
}

/**
 * Judge a host as written (brackets already removed): -> {deny: {reason, range_class}} | {ip} | {name}. No DNS.
 * Reasons: bad-request, numeric-host-noncanonical, literal-blocked, name-blocked.
 */
export function judgeHost(host, extras = []) {
  const h = host.toLowerCase().replace(/\.+$/, '');
  if (!h) return { deny: { reason: 'bad-request', range_class: null } };
  if (h.includes(':')) {
    if (parseV6(h) === null) return { deny: { reason: 'bad-request', range_class: null } };
    const cls = classifyAddress(h, extras);
    return cls ? { deny: { reason: 'literal-blocked', range_class: cls } } : { ip: h };
  }
  if (parseV4(h) !== null) {
    const cls = classifyAddress(h, extras);
    return cls ? { deny: { reason: 'literal-blocked', range_class: cls } } : { ip: h };
  }
  if (NUMERIC_RE.test(h)) return { deny: { reason: 'numeric-host-noncanonical', range_class: null } };
  if (h.length > 253 || !h.split('.').every((l) => LABEL_RE.test(l))) return { deny: { reason: 'bad-request', range_class: null } };
  if (!h.includes('.') || NAME_SUFFIXES.some((s) => h === s || h.endsWith('.' + s))) return { deny: { reason: 'name-blocked', range_class: null } };
  return { name: h };
}
