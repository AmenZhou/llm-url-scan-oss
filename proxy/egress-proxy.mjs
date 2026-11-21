// Deny-by-default egress proxy for a headless browser. Node built-ins only.
//
// Serves CONNECT host:port (HTTPS tunnels) and absolute-URI GET/HEAD/POST (plain HTTP). It refuses anything internal: loopback, private, link-local and
// cloud-metadata, carrier-grade NAT, reserved ranges, internal names, and public-looking names that RESOLVE to such addresses. It resolves every name
// itself, checks every answer, then dials the validated address (never the name again), so a second lookup cannot change the outcome.
// It never logs or stores a host name, URL, address, header or error text: log lines and the /__take buffer carry reasons and range classes only.
//
// Origin-form requests on a slot port are requests to the proxy itself: GET /__take (that slot's denials since the last call, served once) and GET /__health.
import dns from 'node:dns';
import fs from 'node:fs';
import http from 'node:http';
import net from 'node:net';
import { pathToFileURL } from 'node:url';
import { classifyAddress, judgeHost, parseCidrs } from './classify.mjs';

const METHODS = new Set(['GET', 'HEAD', 'POST']);
const HOP = new Set(['connection', 'keep-alive', 'proxy-connection', 'proxy-authorization', 'proxy-authenticate', 'te', 'trailer', 'upgrade']);
const DENIAL_CAP = 256;
const DIAL_TIMEOUT_MS = 10000;
const STATUS = { 'method-not-allowed': 405, 'bad-request': 400, limit: 503 }; // every other refusal is 403

class ConfigError extends Error {}

/** Environment -> config. Throws ConfigError carrying a fixed text (never a value). */
export function loadConfig(env = process.env, argv = []) {
  const bad = (name) => new ConfigError(name + ' is invalid');
  const profile = argv.includes('--test-profile') ? 'test' : env.EGRESS_PROFILE || 'production';
  if (profile !== 'production' && profile !== 'test') throw bad('EGRESS_PROFILE');
  const cidrText = (env.EGRESS_BLOCK_EXTRA_CIDRS ?? '').trim();
  if (!cidrText && profile === 'production') throw new ConfigError('EGRESS_BLOCK_EXTRA_CIDRS is required');
  let extras;
  try {
    extras = parseCidrs(cidrText || 'none');
  } catch {
    throw bad('EGRESS_BLOCK_EXTRA_CIDRS');
  }
  const int = (name, dflt, min = 1, max = Number.MAX_SAFE_INTEGER) => {
    const v = env[name];
    if (v === undefined || v === '') return dflt;
    if (!/^\d{1,15}$/.test(v) || Number(v) < min || Number(v) > max) throw bad(name);
    return Number(v);
  };
  const list = (name) => (env[name] ?? '').split(',').map((s) => s.trim()).filter(Boolean);
  const listen = env.EGRESS_LISTEN || '0.0.0.0:3128';
  const colon = listen.lastIndexOf(':');
  const host = listen.slice(0, colon);
  if (colon < 1 || !/^\d{1,5}$/.test(listen.slice(colon + 1)) || Number(listen.slice(colon + 1)) > 65535) throw bad('EGRESS_LISTEN');
  const slotText = list('EGRESS_SLOT_PORTS');
  if (slotText.some((p) => !/^\d{1,5}$/.test(p) || Number(p) > 65535)) throw bad('EGRESS_SLOT_PORTS');
  const dnsServers = list('EGRESS_DNS_SERVERS');
  try {
    new dns.Resolver().setServers(dnsServers);
  } catch {
    throw bad('EGRESS_DNS_SERVERS');
  }
  const allowedPorts = list('EGRESS_ALLOWED_PORTS').map((p) => {
    if (!/^\d{1,5}$/.test(p) || Number(p) < 1 || Number(p) > 65535) throw bad('EGRESS_ALLOWED_PORTS');
    return Number(p);
  });
  let allowlist = [];
  if (env.EGRESS_ALLOWLIST_FILE) {
    if (profile !== 'test') throw new ConfigError('EGRESS_ALLOWLIST_FILE is only for the test profile');
    try {
      allowlist = JSON.parse(fs.readFileSync(env.EGRESS_ALLOWLIST_FILE, 'utf8')).map((e) => {
        const name = String(e.name).toLowerCase();
        const addr = e.address === undefined ? undefined : String(e.address);
        if (!name || !Number.isInteger(e.port) || (addr !== undefined && !net.isIP(addr))) throw new Error('entry');
        return { name, port: e.port, address: addr };
      });
    } catch {
      throw bad('EGRESS_ALLOWLIST_FILE');
    }
  }
  return {
    profile, host, extras, dnsServers, allowlist,
    slotPorts: slotText.length ? slotText.map(Number) : [Number(listen.slice(colon + 1))],
    allowedPorts: new Set(allowedPorts.length ? allowedPorts : [80, 443]),
    lifetimeMs: int('EGRESS_MAX_LIFETIME_MS', 120000),
    maxBytes: int('EGRESS_MAX_TUNNEL_BYTES', 64 * 1024 * 1024),
    idleMs: int('EGRESS_IDLE_TIMEOUT_MS', 20000),
    maxConns: int('EGRESS_MAX_CONNECTIONS', 2048),
  };
}

/** Default resolver: dns.lookup (all answers) or, with explicit servers, A and AAAA queries. Resolves to an array of address strings. */
export function makeResolver(servers = []) {
  if (!servers.length) return async (name) => (await dns.promises.lookup(name, { all: true, verbatim: true })).map((a) => a.address);
  const r = new dns.promises.Resolver({ timeout: 3000, tries: 2 });
  r.setServers(servers);
  return async (name) => {
    const [a, b] = await Promise.allSettled([r.resolve4(name), r.resolve6(name)]);
    const out = [...(a.value ?? []), ...(b.value ?? [])];
    if (!out.length) throw new Error('no answer');
    return out;
  };
}

/** "host", "host:port" or "[v6]:port" -> {host, port}, or null when malformed. A missing port takes defPort (null = required). */
function parseAuthority(s, defPort) {
  let host, portText;
  if (s.startsWith('[')) {
    const end = s.indexOf(']');
    if (end < 0) return null;
    host = s.slice(1, end);
    const rest = s.slice(end + 1);
    if (rest && !rest.startsWith(':')) return null;
    portText = rest ? rest.slice(1) : undefined;
    if (!host.includes(':')) return null; // brackets are for IPv6 only
  } else {
    const i = s.indexOf(':');
    if (i >= 0 && s.indexOf(':', i + 1) >= 0) return null; // unbracketed IPv6
    host = i >= 0 ? s.slice(0, i) : s;
    portText = i >= 0 ? s.slice(i + 1) : undefined;
  }
  if (!host) return null;
  let port = defPort;
  if (portText !== undefined) {
    if (!/^\d{1,5}$/.test(portText) || Number(portText) < 1 || Number(portText) > 65535) return null;
    port = Number(portText);
  }
  return port === null ? null : { host, port };
}

const portClass = (p) => (p === 80 ? 'http' : p === 443 ? 'https' : p == null ? null : 'other');
const noop = () => {};

/**
 * Build the proxy. hooks (all optional, for tests): resolve(name) -> Promise<string[]>, connect(ip, port) -> net.Socket, log(object).
 * Returns {start() -> Promise<number[]> (bound ports, one per slot), close()}.
 */
export function createProxy(cfg, hooks = {}) {
  const log = hooks.log ?? ((o) => process.stdout.write(JSON.stringify(o) + '\n'));
  const resolve = hooks.resolve ?? makeResolver(cfg.dnsServers);
  const dial = hooks.connect ?? ((ip, port) => net.connect({ host: ip, port }));
  const slots = cfg.slotPorts.map((_, id) => ({ id, denials: [], server: null }));
  const pins = new Map(); // test profile: allowlisted name:port -> {key, ip} pinned at first resolution
  let inflight = 0;
  const live = new Set(); // kill functions of open tunnels and forwards, so close() can end them

  /** Decide about host:port. -> {ips} to dial, or {refuse: {kind: 'deny'|'error', reason, range_class}}. */
  async function decide(rawHost, port) {
    const j = judgeHost(rawHost, cfg.extras);
    const name = rawHost.toLowerCase().replace(/\.+$/, '');
    const entry = cfg.allowlist.find((e) => e.name === name && e.port === port);
    if (entry) {
      if (entry.address) return { ips: [entry.address] };
      let answers;
      try {
        answers = await resolve(name);
      } catch {
        return { refuse: { kind: 'error', reason: 'dns-failed', range_class: null } };
      }
      const key = [...answers].sort().join(',');
      const k = name + ':' + port;
      if (!pins.has(k)) pins.set(k, { key, ip: answers[0] });
      const pin = pins.get(k);
      return pin.key === key && answers.length ? { ips: [pin.ip] } : { refuse: { kind: 'deny', reason: 'allowlist-pin-mismatch', range_class: null } };
    }
    if (j.deny) return { refuse: { kind: 'deny', ...j.deny } };
    let ips = [j.ip];
    if (j.name) {
      try {
        ips = await resolve(j.name);
      } catch {
        return { refuse: { kind: 'error', reason: 'dns-failed', range_class: null } };
      }
      if (!ips.length) return { refuse: { kind: 'error', reason: 'dns-failed', range_class: null } };
      const blocked = ips.map((a) => classifyAddress(a, cfg.extras)).find(Boolean);
      if (blocked) return { refuse: { kind: 'deny', reason: 'resolved-blocked', range_class: blocked } };
    }
    if (!cfg.allowedPorts.has(port)) return { refuse: { kind: 'deny', reason: 'port-not-allowed', range_class: null } };
    return { ips };
  }

  /** Dial the validated addresses in turn; resolves with the first connected socket. */
  function dialAny(ips, port) {
    return new Promise((ok, fail) => {
      const next = (i) => {
        if (i >= ips.length) return fail(new Error('dial'));
        let s;
        try {
          s = dial(ips[i], port);
        } catch {
          return next(i + 1);
        }
        let connected = false;
        const timer = setTimeout(() => s.destroy(), DIAL_TIMEOUT_MS);
        s.on('error', noop);
        const onClose = () => {
          clearTimeout(timer);
          if (!connected) next(i + 1);
        };
        s.once('close', onClose);
        s.once('connect', () => {
          connected = true;
          clearTimeout(timer);
          s.removeListener('close', onClose);
          ok(s);
        });
      };
      next(0);
    });
  }

  function logDeny(slot, r, pc, status, t0) {
    if (slot.denials.length < DENIAL_CAP) slot.denials.push({ decision: r.kind, reason: r.reason, range_class: r.range_class ?? null });
    log({ event: 'request', slot: slot.id, decision: r.kind, reason: r.reason, range_class: r.range_class ?? null, port_class: pc, status, bytes_up: 0, bytes_down: 0, duration_ms: Date.now() - t0 });
  }

  /** One accounting record per proxied request; refuse() or finish() writes its single log line. */
  function begin(slot, pc) {
    const t0 = Date.now();
    let closed = false;
    inflight++;
    const tx = {
      up: 0, down: 0,
      release() {
        if (!closed) { closed = true; inflight--; }
      },
      refuse(r, status) {
        logDeny(slot, r, pc, status, t0);
        tx.release();
      },
      finish(status) {
        log({ event: 'request', slot: slot.id, decision: status ? 'allow' : 'error', reason: status ? null : 'upstream', range_class: null, port_class: pc, status, bytes_up: tx.up, bytes_down: tx.down, duration_ms: Date.now() - t0 });
        tx.release();
      },
    };
    return tx;
  }

  const statusOf = (r) => (r.kind === 'error' ? 502 : STATUS[r.reason] ?? 403);
  const headLines = (r) => `x-egress-decision: ${r.kind}\r\nx-egress-reason: ${r.kind === 'error' ? 'upstream-failed' : r.reason}\r\n`;

  /** Lifetime, idle and byte limits over a client socket and its upstream socket. A limit destroys both; a normal close of one side ends the other
   * gracefully (so buffered data is flushed) and destroys it after a short grace. done() runs once, when both are closed. */
  function guard(tx, a, b, done, pipes = true) {
    let over = false;
    let open = 2;
    const kill = () => {
      a.destroy();
      b.destroy();
    };
    const life = setTimeout(kill, cfg.lifetimeMs);
    live.add(kill);
    const count = (dir) => (chunk) => {
      tx[dir] += chunk.length;
      if (!over && tx.up + tx.down > cfg.maxBytes) { over = true; kill(); }
    };
    for (const [s, other] of [[a, b], [b, a]]) {
      const onClose = () => {
        if (--open === 0) {
          live.delete(kill);
          clearTimeout(life);
          done();
          return;
        }
        if (pipes) other.end(); // an HTTP exchange ends its own client socket through the response
        setTimeout(() => other.destroy(), 2000).unref();
      };
      s.on('error', noop);
      s.setTimeout(cfg.idleMs, kill);
      if (s.destroyed) onClose(); // closed while we were still deciding
      else s.on('close', onClose);
    }
    return count;
  }

  function limitReached(slot, deny) {
    if (inflight < cfg.maxConns) return false;
    const r = { kind: 'deny', reason: 'limit', range_class: null };
    logDeny(slot, r, null, 503, Date.now());
    deny(r);
    return true;
  }

  async function onConnect(slot, req, socket, head) {
    socket.on('error', noop);
    const refuseSocket = (r) => socket.end(`HTTP/1.1 ${statusOf(r)} Refused\r\n${headLines(r)}content-length: 0\r\nconnection: close\r\n\r\n`);
    if (limitReached(slot, refuseSocket)) return;
    const target = parseAuthority(req.url ?? '', null);
    const tx = begin(slot, target ? portClass(target.port) : null);
    if (!target) {
      const r = { kind: 'deny', reason: 'bad-request', range_class: null };
      tx.refuse(r, 400);
      return refuseSocket(r);
    }
    let d, up;
    try {
      d = await decide(target.host, target.port);
      if (!d.refuse) up = await dialAny(d.ips, target.port);
    } catch {
      d = { refuse: { kind: 'error', reason: 'upstream', range_class: null } };
    }
    if (!up) {
      const r = d.refuse ?? { kind: 'error', reason: 'upstream', range_class: null };
      tx.refuse(r, statusOf(r));
      return refuseSocket(r);
    }
    if (socket.destroyed) { up.destroy(); return tx.release(); }
    const count = guard(tx, socket, up, () => tx.finish(200));
    socket.on('data', count('up'));
    up.on('data', count('down'));
    socket.write('HTTP/1.1 200 Connection Established\r\n\r\n');
    if (head?.length) { up.write(head); tx.up += head.length; }
    socket.pipe(up);
    up.pipe(socket);
  }

  async function onRequest(slot, req, res) {
    req.socket.on('error', noop);
    const reply = (status, headers, body) => {
      res.writeHead(status, { 'content-length': Buffer.byteLength(body), connection: 'close', ...headers });
      res.end(body);
    };
    const refuseHttp = (r) => reply(statusOf(r), { 'x-egress-decision': r.kind, 'x-egress-reason': r.kind === 'error' ? 'upstream-failed' : r.reason, 'content-type': 'text/plain' }, r.reason + '\n');
    const url = req.url ?? '';
    if (url.startsWith('/')) { // origin-form: a request to the proxy itself
      if (url === '/__take' || url === '/__health') {
        if (req.method !== 'GET') return reply(405, {}, '');
        if (url === '/__health') return reply(200, { 'content-type': 'text/plain' }, 'ok');
        const body = JSON.stringify({ denials: slot.denials.splice(0) });
        return reply(200, { 'content-type': 'application/json' }, body);
      }
      const r = { kind: 'deny', reason: 'bad-request', range_class: null };
      begin(slot, null).refuse(r, 400);
      return refuseHttp(r);
    }
    if (limitReached(slot, refuseHttp)) return;
    let reason = null;
    let target = null;
    let path = '/';
    const m = /^http:\/\/([^/?#]*)(.*)$/i.exec(url);
    if (!METHODS.has(req.method)) reason = 'method-not-allowed';
    else if (req.headers.upgrade || /\bupgrade\b/i.test(req.headers.connection ?? '')) reason = 'upgrade-not-supported';
    else if (!m || m[1].includes('@') || !(target = parseAuthority(m[1], 80))) reason = 'bad-request';
    else path = m[2].startsWith('/') ? m[2] : '/' + m[2];
    const tx = begin(slot, target ? portClass(target.port) : null);
    if (reason) {
      const r = { kind: 'deny', reason, range_class: null };
      tx.refuse(r, statusOf(r));
      return refuseHttp(r);
    }
    let d, sock;
    try {
      d = await decide(target.host, target.port);
      if (!d.refuse) sock = await dialAny(d.ips, target.port);
    } catch {
      d = { refuse: { kind: 'error', reason: 'upstream', range_class: null } };
    }
    if (!sock) {
      const r = d.refuse ?? { kind: 'error', reason: 'upstream', range_class: null };
      tx.refuse(r, statusOf(r));
      return refuseHttp(r);
    }
    const headers = {};
    for (const [k, v] of Object.entries(req.headers)) if (!HOP.has(k)) headers[k] = v;
    headers.host = target.host.includes(':') ? `[${target.host}]` + (target.port === 80 ? '' : ':' + target.port) : target.host + (target.port === 80 ? '' : ':' + target.port);
    headers.connection = 'close';
    let status = 0;
    const count = guard(tx, req.socket, sock, () => tx.finish(status), false);
    const agent = new http.Agent(); // one request on the socket we already validated and dialled
    agent.createConnection = () => sock;
    const out = http.request({ method: req.method, path, headers, agent });
    out.on('error', noop);
    req.on('data', count('up'));
    req.pipe(out);
    out.on('response', (r) => {
      status = r.statusCode;
      const raw = [];
      for (let i = 0; i < r.rawHeaders.length; i += 2) {
        const k = r.rawHeaders[i].toLowerCase();
        if (!HOP.has(k) && !k.startsWith('x-egress-')) raw.push(r.rawHeaders[i], r.rawHeaders[i + 1]);
      }
      raw.push('Connection', 'close');
      res.writeHead(status, raw);
      r.on('data', count('down'));
      r.pipe(res);
    });
    // upstream died before answering: a dead host, not a refusal
    const noAnswer = () => {
      if (!res.headersSent && !res.writableEnded) {
        const r = { kind: 'error', reason: 'upstream', range_class: null };
        if (slot.denials.length < DENIAL_CAP) slot.denials.push({ decision: 'error', reason: 'upstream', range_class: null });
        refuseHttp(r);
      }
    };
    if (sock.destroyed) setImmediate(noAnswer);
    else sock.once('close', () => setImmediate(noAnswer)); // lets a response that is already in flight win
  }

  function onUpgrade(slot, req, socket) {
    socket.on('error', noop);
    const r = { kind: 'deny', reason: 'upgrade-not-supported', range_class: null };
    begin(slot, null).refuse(r, 403);
    socket.end(`HTTP/1.1 403 Refused\r\n${headLines(r)}content-length: 0\r\nconnection: close\r\n\r\n`);
  }

  return {
    start() {
      return Promise.all(slots.map((slot, i) => new Promise((ok, fail) => {
        const server = http.createServer({ keepAlive: false }, (req, res) => onRequest(slot, req, res).catch(() => res.destroy()));
        server.on('connect', (req, sock, head) => onConnect(slot, req, sock, head).catch(() => sock.destroy()));
        server.on('upgrade', (req, sock) => onUpgrade(slot, req, sock));
        server.on('clientError', (_e, sock) => sock.destroy());
        server.on('connection', (s) => s.on('error', noop));
        server.once('error', fail);
        server.listen(cfg.slotPorts[i], cfg.host, () => {
          slot.server = server;
          ok(server.address().port);
        });
      })));
    },
    async close() {
      for (const kill of [...live]) kill();
      for (const s of slots) {
        s.server?.closeAllConnections();
        await new Promise((ok) => (s.server ? s.server.close(ok) : ok()));
      }
    },
    inflight: () => inflight,
  };
}

async function main() {
  let cfg;
  try {
    cfg = loadConfig(process.env, process.argv.slice(2));
  } catch (e) {
    process.stderr.write((e instanceof ConfigError ? e.message : 'EGRESS config is invalid') + '\n');
    process.exit(2);
  }
  const fatal = () => {
    process.stderr.write('egress-proxy fatal\n');
    process.exit(1);
  };
  process.on('uncaughtException', fatal);
  process.on('unhandledRejection', fatal);
  const proxy = createProxy(cfg);
  const ports = await proxy.start();
  process.stdout.write(JSON.stringify({
    event: 'start', profile: cfg.profile, bind: cfg.host, ports, slots: ports.length, extra_cidrs: cfg.extras.length, dns_servers: cfg.dnsServers.length,
    allowed_ports: cfg.allowedPorts.size, allowlist: cfg.allowlist.length,
  }) + '\n');
  for (const sig of ['SIGTERM', 'SIGINT']) process.on(sig, () => proxy.close().finally(() => process.exit(0)));
}

if (process.argv[1] && import.meta.url === pathToFileURL(process.argv[1]).href) main();
