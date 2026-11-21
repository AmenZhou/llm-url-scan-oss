// node --test proxy/egress-proxy.test.mjs
// No internet: the only upstreams are net/http servers on 127.0.0.1, reached through the test profile's allowlist or through an injected dial hook.
import assert from 'node:assert/strict';
import { spawn } from 'node:child_process';
import http from 'node:http';
import net from 'node:net';
import { after, describe, test } from 'node:test';
import { fileURLToPath } from 'node:url';
import { classifyAddress, judgeHost, parseCidrs } from './classify.mjs';
import { createProxy, loadConfig } from './egress-proxy.mjs';

const SCRIPT = fileURLToPath(new URL('./egress-proxy.mjs', import.meta.url));
const PUBLIC = '93.184.216.34'; // a public address; never dialled for real (the dial hook redirects it to a local server)

// ---------------------------------------------------------------- helpers

const servers = [];
const sockets = new Set();
const listen = (server) => new Promise((ok) => {
  server.on('connection', (s) => { sockets.add(s); s.on('close', () => sockets.delete(s)); });
  server.listen(0, '127.0.0.1', () => { servers.push(server); ok(server.address().port); });
});
const echoServer = () => listen(net.createServer((s) => { s.on('error', () => {}); s.on('data', (d) => s.write(d)); }));
after(() => { sockets.forEach((s) => s.destroy()); servers.forEach((s) => s.close()); });

/** Start a proxy on an ephemeral loopback port. Returns {port, lines, cfg, proxy, close}. */
async function mk(env = {}, hooks = {}, tweak = (c) => c) {
  const lines = [];
  const cfg = tweak(loadConfig({ EGRESS_PROFILE: 'test', EGRESS_BLOCK_EXTRA_CIDRS: 'none', EGRESS_LISTEN: '127.0.0.1:0', ...env }));
  const proxy = createProxy(cfg, { log: (o) => lines.push(o), ...hooks });
  const ports = await proxy.start();
  return { port: ports[0], ports, lines, cfg, proxy, close: () => proxy.close() };
}

/** Send raw bytes, return everything the proxy sends until it closes the connection. */
function exchange(port, payload) {
  return new Promise((ok) => {
    const s = net.connect(port, '127.0.0.1');
    let out = '';
    s.setEncoding('latin1');
    s.on('data', (d) => (out += d));
    s.on('error', () => {});
    s.on('close', () => ok(out));
    s.write(payload);
    setTimeout(() => s.destroy(), 3000).unref();
  });
}
const status = (raw) => Number(/^HTTP\/1\.1 (\d+)/.exec(raw)?.[1]);
const header = (raw, name) => new RegExp('^' + name + ': (.*)\\r$', 'im').exec(raw)?.[1];
const body = (raw) => raw.slice(raw.indexOf('\r\n\r\n') + 4);

const connectRaw = (port, authority) => exchange(port, `CONNECT ${authority} HTTP/1.1\r\nHost: ${authority}\r\n\r\n`);
const getRaw = (port, url, extra = '') => exchange(port, `GET ${url} HTTP/1.1\r\nHost: x\r\n${extra}\r\n`);

/** Open a tunnel; resolves {status, sock} once the proxy's status line has arrived. */
function tunnel(port, authority) {
  return new Promise((ok) => {
    const sock = net.connect(port, '127.0.0.1');
    let buf = '';
    sock.on('error', () => {});
    sock.write(`CONNECT ${authority} HTTP/1.1\r\nHost: ${authority}\r\n\r\n`);
    const onData = (d) => {
      buf += d.toString('latin1');
      if (buf.includes('\r\n\r\n')) {
        sock.off('data', onData);
        ok({ status: status(buf), sock, buf });
      }
    };
    sock.on('data', onData);
    sock.on('close', () => ok({ status: status(buf), sock, buf }));
  });
}
const nextData = (sock) => new Promise((ok) => sock.once('data', (d) => ok(d.toString())));
const closed = (sock, ms = 3000) => new Promise((ok) => { if (sock.destroyed) return ok(true); sock.on('close', () => ok(true)); setTimeout(() => ok(false), ms).unref(); });

function take(port) {
  return new Promise((ok, fail) => {
    http.get({ host: '127.0.0.1', port, path: '/__take', agent: false }, (res) => {
      let data = '';
      res.on('data', (d) => (data += d));
      res.on('end', () => ok({ headers: res.headers, json: JSON.parse(data), raw: data }));
    }).on('error', fail);
  });
}

const reasonOf = (raw) => header(raw, 'x-egress-reason');

// ---------------------------------------------------------------- classifier

describe('classifier: addresses', () => {
  const blocked = {
    loopback_or_unspecified: ['0.0.0.0', '0.1.2.3', '127.0.0.1', '127.255.255.254', '::', '::1'],
    private: ['10.0.0.1', '10.255.255.255', '100.64.0.1', '100.127.255.255', '172.16.0.1', '172.31.255.255', '192.168.0.1', '192.168.255.255', 'fc00::1', 'fd12:3456::1'],
    link_local_or_metadata: ['169.254.169.254', '169.254.0.1', 'fe80::1', 'febf::1', 'fd00:ec2::254'],
    reserved_or_doc: ['192.0.0.1', '192.0.0.255', '192.0.2.5', '192.88.99.1', '198.18.0.1', '198.19.255.255', '198.51.100.1', '203.0.113.9', '224.0.0.1', '239.255.255.250',
      '240.0.0.1', '255.255.255.255', 'ff02::1', 'ff00::', '2001:db8::1', '3fff::1'],
    v6_other: ['64:ff9b:1::1', '2002::1', '2001::1', '2001:1::5', '4000::1', '8000::1', 'fec0::1', '100::1', '::ffff:8.8.8.8', '64:ff9b::808:808', '::808:808'],
  };
  for (const [cls, list] of Object.entries(blocked)) {
    for (const a of list) test(`${a} is ${cls}`, () => assert.equal(classifyAddress(a), cls));
  }

  test('mapped and compatible forms take the class of the embedded IPv4 address', () => {
    for (const [a, cls] of [['::ffff:127.0.0.1', 'loopback_or_unspecified'], ['::ffff:7f00:1', 'loopback_or_unspecified'], ['::ffff:10.1.2.3', 'private'],
      ['::ffff:a9fe:a9fe', 'link_local_or_metadata'], ['::127.0.0.1', 'loopback_or_unspecified'], ['::10.0.0.1', 'private'], ['64:ff9b::7f00:1', 'loopback_or_unspecified'],
      ['0:0:0:0:0:ffff:c0a8:1', 'private']]) assert.equal(classifyAddress(a), cls, a);
  });

  test('public addresses are not blocked', () => {
    for (const a of ['1.1.1.1', '8.8.8.8', '93.184.216.34', '172.15.255.255', '172.32.0.1', '100.63.255.255', '100.128.0.1', '169.253.1.1', '198.17.255.255', '198.20.0.1',
      '223.255.255.255', '2606:4700::1111', '2a00:1450:4001::200e', '2001:4860:4860::8888', '2400:cb00::1']) assert.equal(classifyAddress(a), null, a);
  });

  test('text that is not an address is blocked', () => {
    for (const a of ['', 'example.com', '1.2.3', '1.2.3.256', '::g', '1::2::3', 'fe80::1%eth0']) assert.equal(classifyAddress(a), 'v6_other', a);
  });

  test('extra CIDRs block otherwise public ranges as own_or_extra; built-in classes win', () => {
    const extras = parseCidrs('8.8.8.0/24, 2606:4700::/32, 10.80.0.0/16');
    assert.equal(classifyAddress('8.8.8.8', extras), 'own_or_extra');
    assert.equal(classifyAddress('8.8.9.8', extras), null);
    assert.equal(classifyAddress('2606:4700::1111', extras), 'own_or_extra');
    assert.equal(classifyAddress('10.80.5.10', extras), 'private');
  });

  test('parseCidrs: none is empty; bad entries throw', () => {
    assert.deepEqual(parseCidrs('none'), []);
    for (const bad of ['10.0.0.0', '10.0.0.0/33', '::/129', 'abc/8', '10.0.0.0/', '1.2.3/8']) assert.throws(() => parseCidrs(bad), bad);
  });
});

describe('classifier: hosts as written', () => {
  const reasonFor = (h) => judgeHost(h).deny?.reason ?? (judgeHost(h).ip ? 'ip' : 'name');

  test('names that are internal by spelling', () => {
    for (const h of ['localhost', 'LOCALHOST', 'localhost.', 'a.localhost', 'printer.local', 'db.internal', 'host.docker.internal', 'gateway.docker.internal', 'x.localdomain',
      'router.home.arpa', 'svc.cluster.local', 'a.b.cluster.local', 'intranet', 'singlelabel', 'nas.lan', 'x.home', 'x.corp', 'x.intranet', 'x.private', 'x.test', 'x.invalid', 'a.svc'])
      assert.equal(reasonFor(h), 'name-blocked', h);
  });

  test('public-looking names pass the spelling check', () => {
    for (const h of ['example.com', 'www.example.co.uk', 'xn--bcher-kva.example', 'a-b.example', 'localhost.example.com', 'notlocal.com', 'internal.example.com'])
      assert.equal(reasonFor(h), 'name', h);
  });

  test('non-canonical numeric hosts', () => {
    for (const h of ['2130706433', '0x7f.1', '0x7f000001', '017700000001', '127.1', '127.0.1', '0177.0.0.1', '1.2.3.256', '1.2.3.04', '1.2.3.4.5', '0', '4294967296', '0x7F.0X0.0.1', '10.1'])
      assert.equal(reasonFor(h), 'numeric-host-noncanonical', h);
  });

  test('IP literals', () => {
    assert.deepEqual(judgeHost('127.0.0.1').deny, { reason: 'literal-blocked', range_class: 'loopback_or_unspecified' });
    assert.deepEqual(judgeHost('169.254.169.254').deny, { reason: 'literal-blocked', range_class: 'link_local_or_metadata' });
    assert.deepEqual(judgeHost('::1').deny, { reason: 'literal-blocked', range_class: 'loopback_or_unspecified' });
    assert.deepEqual(judgeHost('::ffff:192.168.1.1').deny, { reason: 'literal-blocked', range_class: 'private' });
    assert.deepEqual(judgeHost('8.8.8.8'), { ip: '8.8.8.8' });
    assert.deepEqual(judgeHost('2606:4700::1111'), { ip: '2606:4700::1111' });
    assert.equal(judgeHost('::ffff:8.8.8.8').deny.reason, 'literal-blocked'); // every mapped form is refused, public or not
  });

  test('malformed hosts', () => {
    for (const h of ['', '...', 'a..b', 'bad host', 'a/b', 'ex%41mple.com', 'a:b', '-a.com', 'fe80::1%eth0']) assert.equal(reasonFor(h), 'bad-request', h);
  });
});

// ---------------------------------------------------------------- config and process start

describe('config', () => {
  test('production without extra CIDRs is refused with a fixed text; none is accepted', () => {
    assert.throws(() => loadConfig({ EGRESS_PROFILE: 'production' }), /EGRESS_BLOCK_EXTRA_CIDRS is required/);
    assert.throws(() => loadConfig({ EGRESS_PROFILE: 'production', EGRESS_BLOCK_EXTRA_CIDRS: '' }), /EGRESS_BLOCK_EXTRA_CIDRS is required/);
    assert.throws(() => loadConfig({}), /is required/); // production is the default profile
    assert.equal(loadConfig({ EGRESS_PROFILE: 'production', EGRESS_BLOCK_EXTRA_CIDRS: 'none' }).extras.length, 0);
  });

  test('defaults', () => {
    const c = loadConfig({ EGRESS_BLOCK_EXTRA_CIDRS: 'none' });
    assert.deepEqual([c.host, c.slotPorts, [...c.allowedPorts]], ['0.0.0.0', [3128], [80, 443]]);
    assert.deepEqual([c.lifetimeMs, c.maxBytes, c.idleMs, c.maxConns], [120000, 67108864, 20000, 2048]);
  });

  test('slot ports, allowed ports, extra CIDRs', () => {
    const c = loadConfig({ EGRESS_BLOCK_EXTRA_CIDRS: '10.80.0.0/16,192.0.2.0/24', EGRESS_SLOT_PORTS: '3128, 3129', EGRESS_ALLOWED_PORTS: '80,443,8443', EGRESS_LISTEN: '127.0.0.1:3000' });
    assert.deepEqual([c.host, c.slotPorts, [...c.allowedPorts], c.extras.length], ['127.0.0.1', [3128, 3129], [80, 443, 8443], 2]);
  });

  test('invalid values give fixed texts that never repeat the value', () => {
    const secret = 'zz-secret-value-9';
    const cases = { EGRESS_BLOCK_EXTRA_CIDRS: secret, EGRESS_LISTEN: secret, EGRESS_SLOT_PORTS: secret, EGRESS_ALLOWED_PORTS: secret, EGRESS_DNS_SERVERS: secret,
      EGRESS_MAX_LIFETIME_MS: secret, EGRESS_MAX_TUNNEL_BYTES: '-5', EGRESS_IDLE_TIMEOUT_MS: '0', EGRESS_MAX_CONNECTIONS: '1.5', EGRESS_PROFILE: secret };
    for (const [k, v] of Object.entries(cases)) {
      try {
        loadConfig({ EGRESS_BLOCK_EXTRA_CIDRS: 'none', EGRESS_PROFILE: 'production', [k]: v });
        assert.fail(k + ' accepted');
      } catch (e) {
        assert.match(e.message, /^EGRESS_[A-Z_]+ is invalid$/, k);
        assert.ok(!e.message.includes(v) || v === '0', k);
      }
    }
  });

  test('the allowlist file is for the test profile only', () => {
    assert.throws(() => loadConfig({ EGRESS_PROFILE: 'production', EGRESS_BLOCK_EXTRA_CIDRS: 'none', EGRESS_ALLOWLIST_FILE: '/x' }), /only for the test profile/);
    assert.throws(() => loadConfig({ EGRESS_PROFILE: 'test', EGRESS_ALLOWLIST_FILE: '/does/not/exist.json' }), /EGRESS_ALLOWLIST_FILE is invalid/);
  });

  test('--test-profile selects the test profile', () => {
    assert.equal(loadConfig({ EGRESS_PROFILE: 'production' }, ['--test-profile']).profile, 'test');
  });
});

function run(env, ms = 4000) {
  return new Promise((ok) => {
    const p = spawn(process.execPath, [SCRIPT], { env: { PATH: process.env.PATH, ...env }, stdio: ['ignore', 'pipe', 'pipe'] });
    let out = '', err = '';
    p.stdout.on('data', (d) => (out += d));
    p.stderr.on('data', (d) => (err += d));
    p.on('close', (code) => ok({ code, out, err }));
    p.on('spawn', () => {
      const t = setInterval(() => { if (out.includes('\n')) { clearInterval(t); p.kill('SIGTERM'); } }, 20);
      setTimeout(() => { clearInterval(t); p.kill('SIGKILL'); }, ms).unref();
    });
  });
}

describe('process', () => {
  test('production profile exits 2 with a fixed text when extra CIDRs are unset or empty', async () => {
    for (const env of [{ EGRESS_PROFILE: 'production' }, { EGRESS_PROFILE: 'production', EGRESS_BLOCK_EXTRA_CIDRS: '' }]) {
      const r = await run(env);
      assert.equal(r.code, 2);
      assert.equal(r.err.trim(), 'EGRESS_BLOCK_EXTRA_CIDRS is required');
      assert.equal(r.out, '');
    }
  });

  test('an invalid CIDR exits 2 without echoing it', async () => {
    const r = await run({ EGRESS_PROFILE: 'production', EGRESS_BLOCK_EXTRA_CIDRS: '999.1.1.1/8' });
    assert.equal(r.code, 2);
    assert.ok(!r.err.includes('999'));
  });

  test('with the word none it starts and prints one counts-only start line', async () => {
    const r = await run({ EGRESS_PROFILE: 'production', EGRESS_BLOCK_EXTRA_CIDRS: 'none', EGRESS_LISTEN: '127.0.0.1:0', EGRESS_SLOT_PORTS: '0,0' });
    const first = JSON.parse(r.out.split('\n')[0]);
    assert.equal(first.event, 'start');
    assert.equal(first.slots, 2);
    assert.equal(first.extra_cidrs, 0);
    assert.equal(first.bind, '127.0.0.1');
    assert.equal(r.err, '');
  });

  test('the start line carries counts, not ranges', async () => {
    const r = await run({ EGRESS_PROFILE: 'production', EGRESS_BLOCK_EXTRA_CIDRS: '10.80.0.0/16,203.0.113.0/24', EGRESS_LISTEN: '127.0.0.1:0', EGRESS_DNS_SERVERS: '9.9.9.9' });
    const first = JSON.parse(r.out.split('\n')[0]);
    assert.equal(first.extra_cidrs, 2);
    assert.equal(first.dns_servers, 1);
    assert.ok(!r.out.includes('10.80') && !r.out.includes('203.0.113') && !r.out.includes('9.9.9.9'));
  });

  test('a fatal error logs a fixed code and exits non-zero', async () => {
    const taken = net.createServer();
    const port = await listen(taken);
    const r = await run({ EGRESS_PROFILE: 'production', EGRESS_BLOCK_EXTRA_CIDRS: 'none', EGRESS_LISTEN: '127.0.0.1:' + port });
    assert.equal(r.code, 1);
    assert.equal(r.err.trim(), 'egress-proxy fatal');
    assert.ok(!r.err.includes('EADDRINUSE') && !r.err.includes(String(port)));
  });
});

// ---------------------------------------------------------------- refusals

describe('refusals through CONNECT and absolute-URI GET', () => {
  const table = [
    ['127.0.0.1:443', 'literal-blocked', 'loopback_or_unspecified'],
    ['[::1]:443', 'literal-blocked', 'loopback_or_unspecified'],
    ['[::ffff:127.0.0.1]:443', 'literal-blocked', 'loopback_or_unspecified'],
    ['[::ffff:7f00:1]:443', 'literal-blocked', 'loopback_or_unspecified'],
    ['169.254.169.254:80', 'literal-blocked', 'link_local_or_metadata'],
    ['10.0.0.5:80', 'literal-blocked', 'private'],
    ['100.64.0.1:80', 'literal-blocked', 'private'],
    ['[fd00::1]:80', 'literal-blocked', 'private'],
    ['198.18.0.1:80', 'literal-blocked', 'reserved_or_doc'],
    ['224.0.0.1:80', 'literal-blocked', 'reserved_or_doc'],
    ['[2002::1]:80', 'literal-blocked', 'v6_other'],
    ['localhost:7100', 'name-blocked', null],
    ['host.docker.internal:80', 'name-blocked', null],
    ['db.internal:443', 'name-blocked', null],
    ['intranet:80', 'name-blocked', null],
    ['2130706433:80', 'numeric-host-noncanonical', null],
    ['0x7f.1:80', 'numeric-host-noncanonical', null],
    ['017700000001:80', 'numeric-host-noncanonical', null],
    ['127.1:80', 'numeric-host-noncanonical', null],
    ['8.8.8.8:25', 'port-not-allowed', null],
    ['[2606:4700::1111]:22', 'port-not-allowed', null],
  ];
  for (const [authority, reason, cls] of table) {
    test(`${authority} -> ${reason}`, async () => {
      const dialed = [];
      const p = await mk({}, { connect: (ip) => { dialed.push(ip); throw new Error('must not dial'); } });
      const viaConnect = await connectRaw(p.port, authority);
      assert.equal(status(viaConnect), 403);
      assert.equal(reasonOf(viaConnect), reason);
      assert.equal(header(viaConnect, 'x-egress-decision'), 'deny');
      const viaGet = await getRaw(p.port, 'http://' + authority + '/x');
      assert.equal(status(viaGet), 403);
      assert.equal(reasonOf(viaGet), reason);
      const t = await take(p.port);
      assert.deepEqual(t.json.denials, [{ decision: 'deny', reason, range_class: cls }, { decision: 'deny', reason, range_class: cls }]);
      assert.deepEqual(dialed, []);
      await p.close();
    });
  }

  test('bad-request for malformed targets', async () => {
    const p = await mk();
    for (const raw of [
      connectRaw(p.port, 'example.com'), // no port
      connectRaw(p.port, 'example.com:0'),
      connectRaw(p.port, 'example.com:99999'),
      connectRaw(p.port, '::1:80'),
      connectRaw(p.port, 'user@example.com:443'),
      getRaw(p.port, 'http://[::1/x'),
      getRaw(p.port, 'http://user:pw@example.com/'),
      getRaw(p.port, 'ftp://example.com/'),
      getRaw(p.port, 'https://example.com/'),
      getRaw(p.port, 'http:///x'),
      getRaw(p.port, '/not-a-proxy-path'),
    ]) {
      const r = await raw;
      assert.equal(status(r), 400, r);
      assert.equal(reasonOf(r), 'bad-request');
    }
    await p.close();
  });

  test('other methods get 405 method-not-allowed', async () => {
    const p = await mk();
    for (const m of ['PUT', 'DELETE', 'PATCH', 'OPTIONS', 'TRACE']) {
      const r = await exchange(p.port, `${m} http://example.com/ HTTP/1.1\r\nHost: x\r\n\r\n`);
      assert.equal(status(r), 405, m);
      assert.equal(reasonOf(r), 'method-not-allowed');
    }
    const t = await take(p.port);
    assert.equal(t.json.denials.length, 5);
    assert.ok(t.json.denials.every((d) => d.reason === 'method-not-allowed' && d.range_class === null));
    await p.close();
  });

  test('Upgrade and websocket requests are refused', async () => {
    const p = await mk();
    for (const extra of ['Upgrade: websocket\r\nConnection: Upgrade\r\n', 'Connection: upgrade\r\n', 'Upgrade: h2c\r\n']) {
      const r = await getRaw(p.port, 'http://example.com/ws', extra);
      assert.equal(status(r), 403, extra);
      assert.equal(reasonOf(r), 'upgrade-not-supported');
    }
    assert.equal((await take(p.port)).json.denials.length, 3);
    await p.close();
  });

  test('the body of a refusal never contains the target', async () => {
    const p = await mk();
    const r = await getRaw(p.port, 'http://secret-host-zzz.localhost/path?q=secret-query');
    assert.ok(!r.includes('secret'));
    await p.close();
  });
});

describe('/__take and /__health', () => {
  test('returns the slot denials as JSON once, then empty', async () => {
    const p = await mk();
    await connectRaw(p.port, 'localhost:443');
    await connectRaw(p.port, '10.0.0.1:443');
    const a = await take(p.port);
    assert.equal(a.headers['content-type'], 'application/json');
    assert.equal(Number(a.headers['content-length']), Buffer.byteLength(a.raw));
    assert.deepEqual(a.json.denials.map((d) => [d.reason, d.range_class]), [['name-blocked', null], ['literal-blocked', 'private']]);
    assert.deepEqual((await take(p.port)).json, { denials: [] });
    await p.close();
  });

  test('entries hold no host and no address', async () => {
    const p = await mk();
    await connectRaw(p.port, '10.9.8.7:443');
    await getRaw(p.port, 'http://secret-host-zzz.localhost/');
    const raw = (await take(p.port)).raw;
    assert.ok(!raw.includes('10.9.8.7') && !raw.includes('secret-host-zzz'));
    for (const d of JSON.parse(raw).denials) assert.deepEqual(Object.keys(d).sort(), ['decision', 'range_class', 'reason']);
    await p.close();
  });

  test('each slot has its own buffer', async () => {
    const p = await mk({ EGRESS_SLOT_PORTS: '0,0,0' });
    await connectRaw(p.ports[1], 'localhost:443');
    assert.deepEqual((await take(p.ports[0])).json.denials, []);
    assert.equal((await take(p.ports[1])).json.denials.length, 1);
    assert.deepEqual((await take(p.ports[1])).json.denials, []);
    assert.deepEqual((await take(p.ports[2])).json.denials, []);
    assert.deepEqual(p.lines.map((l) => l.slot), [1]);
    await p.close();
  });

  test('the buffer is capped', async () => {
    const p = await mk();
    for (let i = 0; i < 300; i++) p.lines.length < 1000 && (await exchange(p.port, 'CONNECT localhost:80 HTTP/1.1\r\n\r\n'));
    const t = await take(p.port);
    assert.ok(t.json.denials.length > 0 && t.json.denials.length <= 256, String(t.json.denials.length));
    await p.close();
  });

  test('/__take only answers GET; /__health answers 200', async () => {
    const p = await mk();
    assert.equal(status(await exchange(p.port, 'POST /__take HTTP/1.1\r\nHost: x\r\ncontent-length: 0\r\n\r\n')), 405);
    assert.equal(status(await exchange(p.port, 'GET /__health HTTP/1.1\r\nHost: x\r\n\r\n')), 200);
    await p.close();
  });

  test('a proxied absolute-URI request to the proxy itself is refused as a loopback literal', async () => {
    const p = await mk();
    const r = await getRaw(p.port, `http://127.0.0.1:${p.port}/__take`);
    assert.equal(reasonOf(r), 'literal-blocked');
    await p.close();
  });
});

// ---------------------------------------------------------------- resolution and pinning

describe('resolved-blocked and anti-rebinding', () => {
  test('any blocked answer refuses the name', async () => {
    const answers = {
      'one.example': ['10.0.0.1'],
      'two.example': [PUBLIC, '127.0.0.1'],
      'three.example': ['2606:4700::1111', '::1'],
      'four.example': ['::ffff:169.254.169.254'],
      'five.example': ['100.64.1.1'],
    };
    const classes = { 'one.example': 'private', 'two.example': 'loopback_or_unspecified', 'three.example': 'loopback_or_unspecified', 'four.example': 'link_local_or_metadata', 'five.example': 'private' };
    const p = await mk({}, { resolve: async (n) => answers[n], connect: () => { throw new Error('must not dial'); } });
    for (const n of Object.keys(answers)) {
      const r = await connectRaw(p.port, n + ':443');
      assert.equal(reasonOf(r), 'resolved-blocked', n);
    }
    assert.deepEqual((await take(p.port)).json.denials.map((d) => d.range_class), Object.values(classes));
    await p.close();
  });

  test('extra CIDRs refuse a resolved answer as own_or_extra', async () => {
    const p = await mk({ EGRESS_BLOCK_EXTRA_CIDRS: '93.184.216.0/24' }, { resolve: async () => [PUBLIC] });
    assert.equal(reasonOf(await connectRaw(p.port, 'x.example:443')), 'resolved-blocked');
    assert.equal((await take(p.port)).json.denials[0].range_class, 'own_or_extra');
    await p.close();
  });

  test('a resolver failure or an empty answer is an error, not a refusal', async () => {
    for (const resolve of [async () => { throw new Error('boom-secret'); }, async () => []]) {
      const p = await mk({}, { resolve });
      const r = await connectRaw(p.port, 'gone.example:443');
      assert.equal(status(r), 502);
      assert.equal(header(r, 'x-egress-decision'), 'error');
      assert.deepEqual((await take(p.port)).json.denials, [{ decision: 'error', reason: 'dns-failed', range_class: null }]);
      assert.ok(!JSON.stringify(p.lines).includes('boom-secret'));
      await p.close();
    }
  });

  test('the validated address is the one dialled, with one lookup per request', async () => {
    const echo = await echoServer();
    const dialed = [];
    let calls = 0;
    const p = await mk({}, {
      resolve: async () => (++calls === 1 ? [PUBLIC] : ['127.0.0.1']), // a second lookup would rebind to loopback
      connect: (ip) => { dialed.push(ip); return net.connect({ host: '127.0.0.1', port: echo }); },
    });
    const t = await tunnel(p.port, 'rebind.example:443');
    assert.equal(t.status, 200);
    t.sock.write('ping');
    assert.equal(await nextData(t.sock), 'ping');
    assert.equal(calls, 1);
    assert.deepEqual(dialed, [PUBLIC]); // the address, never the name
    t.sock.destroy();
    const second = await connectRaw(p.port, 'rebind.example:443'); // the next request resolves again and is refused on its own answer
    assert.equal(reasonOf(second), 'resolved-blocked');
    assert.equal(calls, 2);
    assert.deepEqual(dialed, [PUBLIC]);
    await p.close();
  });

  test('plain HTTP dials the validated address and sends the original Host', async () => {
    const seen = [];
    const up = await listen(http.createServer((req, res) => { seen.push(req.headers.host); res.end('ok'); }));
    const dialed = [];
    let calls = 0;
    const p = await mk({}, {
      resolve: async () => (++calls === 1 ? [PUBLIC] : ['127.0.0.1']),
      connect: (ip) => { dialed.push(ip); return net.connect({ host: '127.0.0.1', port: up }); },
    });
    const r = await getRaw(p.port, 'http://rebind.example/page');
    assert.equal(status(r), 200);
    assert.deepEqual([calls, dialed, seen], [1, [PUBLIC], ['rebind.example']]);
    await p.close();
  });

  test('a literal public address is dialled without any lookup', async () => {
    const echo = await echoServer();
    const dialed = [];
    const p = await mk({}, { resolve: async () => { throw new Error('no lookup expected'); }, connect: (ip, port) => { dialed.push([ip, port]); return net.connect({ host: '127.0.0.1', port: echo }); } });
    const t = await tunnel(p.port, `${PUBLIC}:443`);
    assert.equal(t.status, 200);
    assert.deepEqual(dialed, [[PUBLIC, 443]]);
    t.sock.destroy();
    await p.close();
  });

  test('later answers are tried when the first address cannot be reached', async () => {
    const echo = await echoServer();
    const dialed = [];
    const p = await mk({}, {
      resolve: async () => [PUBLIC, '8.8.4.4'],
      connect: (ip) => { dialed.push(ip); return net.connect({ host: '127.0.0.1', port: ip === PUBLIC ? 1 : echo }); },
    });
    const t = await tunnel(p.port, 'multi.example:443');
    assert.equal(t.status, 200);
    assert.deepEqual(dialed, [PUBLIC, '8.8.4.4']);
    t.sock.destroy();
    await p.close();
  });

  test('an unreachable upstream is an error decision (502), not a refusal', async () => {
    const p = await mk({}, { resolve: async () => [PUBLIC], connect: () => net.connect({ host: '127.0.0.1', port: 1 }) });
    const r = await connectRaw(p.port, 'down.example:443');
    assert.equal(status(r), 502);
    assert.equal((await take(p.port)).json.denials[0].decision, 'error');
    const g = await getRaw(p.port, 'http://down.example/');
    assert.equal(status(g), 502);
    await p.close();
  });
});

describe('test profile allowlist', () => {
  test('an allowlisted name with a fixed address reaches a local fixture, ignoring port policy and extra CIDRs', async () => {
    const up = await listen(http.createServer((req, res) => res.end('fixture')));
    const p = await mk({ EGRESS_BLOCK_EXTRA_CIDRS: '127.0.0.0/8' }, { resolve: async () => { throw new Error('no lookup'); } },
      (c) => ({ ...c, allowlist: [{ name: 'fx.example', port: up, address: '127.0.0.1' }] }));
    const r = await getRaw(p.port, `http://fx.example:${up}/ok`);
    assert.equal(status(r), 200);
    assert.equal(body(r), 'fixture');
    await p.close();
  });

  test('without an address the first resolution is the pin; a changed answer is allowlist-pin-mismatch', async () => {
    const echo = await echoServer();
    let answer = ['127.0.0.1'];
    const p = await mk({}, { resolve: async () => answer }, (c) => ({ ...c, allowlist: [{ name: 'fx.example', port: echo }] }));
    const t = await tunnel(p.port, `fx.example:${echo}`);
    assert.equal(t.status, 200);
    t.sock.destroy();
    answer = ['10.80.5.99'];
    const r = await connectRaw(p.port, `fx.example:${echo}`);
    assert.equal(reasonOf(r), 'allowlist-pin-mismatch');
    answer = ['127.0.0.1', '8.8.8.8'];
    assert.equal(reasonOf(await connectRaw(p.port, `fx.example:${echo}`)), 'allowlist-pin-mismatch');
    answer = ['127.0.0.1'];
    assert.equal((await tunnel(p.port, `fx.example:${echo}`)).status, 200);
    assert.deepEqual((await take(p.port)).json.denials.map((d) => d.reason), ['allowlist-pin-mismatch', 'allowlist-pin-mismatch']);
    await p.close();
  });

  test('anything not allowlisted is judged by the normal rules (name or port differs)', async () => {
    const p = await mk({ EGRESS_BLOCK_EXTRA_CIDRS: '10.80.0.0/16' }, { resolve: async () => ['10.80.5.10'] }, (c) => ({ ...c, allowlist: [{ name: 'fx.example', port: 8080, address: '127.0.0.1' }] }));
    const other = await getRaw(p.port, 'http://refused.example:8080/ok');
    assert.equal(reasonOf(other), 'resolved-blocked'); // resolution is judged before the port policy
    assert.equal((await take(p.port)).json.denials[0].range_class, 'private');
    assert.equal(reasonOf(await getRaw(p.port, 'http://fx.example:9999/ok')), 'resolved-blocked'); // same name, other port: not allowlisted
    await p.close();
  });

  test('the allowlist file is read (format: [{id, name, port}])', async () => {
    const { writeFileSync, mkdtempSync } = await import('node:fs');
    const { tmpdir } = await import('node:os');
    const { join } = await import('node:path');
    const f = join(mkdtempSync(join(tmpdir(), 'egress-')), 'allow.json');
    writeFileSync(f, JSON.stringify([{ id: 'fx', name: 'FX.example', port: 8080 }]));
    const c = loadConfig({ EGRESS_PROFILE: 'test', EGRESS_ALLOWLIST_FILE: f });
    assert.deepEqual(c.allowlist, [{ name: 'fx.example', port: 8080, address: undefined }]);
  });
});

describe('port policy', () => {
  test('default ports are 80 and 443; EGRESS_ALLOWED_PORTS replaces them', async () => {
    const echo = await echoServer();
    const hooks = { connect: () => net.connect({ host: '127.0.0.1', port: echo }) };
    const dflt = await mk({}, hooks);
    for (const a of [`${PUBLIC}:80`, `${PUBLIC}:443`]) assert.equal((await tunnel(dflt.port, a)).status, 200, a);
    for (const a of [`${PUBLIC}:8080`, `${PUBLIC}:22`, `${PUBLIC}:8443`]) assert.equal(reasonOf(await connectRaw(dflt.port, a)), 'port-not-allowed', a);
    await dflt.close();
    const custom = await mk({ EGRESS_ALLOWED_PORTS: '8443' }, hooks);
    assert.equal((await tunnel(custom.port, `${PUBLIC}:8443`)).status, 200);
    assert.equal(reasonOf(await connectRaw(custom.port, `${PUBLIC}:443`)), 'port-not-allowed');
    await custom.close();
  });

  test('plain HTTP defaults to port 80 and is judged on the URL port', async () => {
    const echo = await echoServer();
    const p = await mk({}, { connect: (ip, port) => net.connect({ host: '127.0.0.1', port: port === 80 ? echo : 1 }) });
    assert.equal(reasonOf(await getRaw(p.port, `http://${PUBLIC}:8080/`)), 'port-not-allowed');
    assert.equal((await take(p.port)).json.denials[0].reason, 'port-not-allowed');
    await p.close();
  });
});

// ---------------------------------------------------------------- forwarding

describe('forwarding', () => {
  test('CONNECT tunnels bytes both ways and reports allow with counts', async () => {
    const echo = await echoServer();
    const p = await mk({}, {}, (c) => ({ ...c, allowlist: [{ name: 'fx.example', port: echo, address: '127.0.0.1' }] }));
    const t = await tunnel(p.port, `fx.example:${echo}`);
    assert.equal(t.status, 200);
    t.sock.write('hello tunnel');
    assert.equal(await nextData(t.sock), 'hello tunnel');
    t.sock.destroy();
    await new Promise((ok) => setTimeout(ok, 150));
    const line = p.lines.find((l) => l.decision === 'allow');
    assert.ok(line, JSON.stringify(p.lines));
    assert.deepEqual([line.event, line.slot, line.status, line.bytes_up, line.bytes_down, line.reason, line.range_class], ['request', 0, 200, 12, 12, null, null]);
    assert.equal(line.port_class, 'other');
    assert.equal(typeof line.duration_ms, 'number');
    await p.close();
  });

  test('absolute-URI GET, HEAD and POST are forwarded; hop headers and x-egress-* from upstream are dropped', async () => {
    const seen = [];
    const up = await listen(http.createServer((req, res) => {
      let data = '';
      req.on('data', (d) => (data += d));
      req.on('end', () => {
        seen.push({ method: req.method, url: req.url, host: req.headers.host, proxyConn: req.headers['proxy-connection'], proxyAuth: req.headers['proxy-authorization'], data, cookie: req.headers.cookie });
        res.setHeader('x-egress-decision', 'deny');
        res.setHeader('x-egress-reason', 'name-blocked');
        res.setHeader('set-cookie', ['a=1', 'b=2']);
        res.setHeader('content-type', 'text/plain');
        res.end(req.method === 'HEAD' ? '' : 'reply:' + data);
      });
    }));
    const p = await mk({}, {}, (c) => ({ ...c, allowlist: [{ name: 'fx.example', port: up, address: '127.0.0.1' }] }));
    const base = `http://fx.example:${up}`;
    const get = await getRaw(p.port, base + '/a/b?x=1', 'Proxy-Connection: keep-alive\r\nProxy-Authorization: Basic abc\r\nCookie: k=v\r\n');
    assert.equal(status(get), 200);
    assert.equal(body(get), 'reply:');
    assert.equal(header(get, 'x-egress-decision'), undefined);
    assert.equal(header(get, 'x-egress-reason'), undefined);
    assert.equal((get.match(/^set-cookie:/gim) ?? []).length, 2);
    const post = await exchange(p.port, `POST ${base}/submit HTTP/1.1\r\nHost: x\r\nContent-Length: 5\r\n\r\nhello`);
    assert.equal(body(post), 'reply:hello');
    const head = await exchange(p.port, `HEAD ${base}/h HTTP/1.1\r\nHost: x\r\n\r\n`);
    assert.equal(status(head), 200);
    assert.deepEqual(seen.map((s) => [s.method, s.url, s.host]), [['GET', '/a/b?x=1', `fx.example:${up}`], ['POST', '/submit', `fx.example:${up}`], ['HEAD', '/h', `fx.example:${up}`]]);
    assert.equal(seen[0].proxyConn, undefined);
    assert.equal(seen[0].proxyAuth, undefined);
    assert.equal(seen[0].cookie, 'k=v');
    assert.equal(seen[1].data, 'hello');
    await p.close();
  });

  test('the default Host omits port 80 and a bare authority gets path /', async () => {
    const seen = [];
    const up = await listen(http.createServer((req, res) => { seen.push([req.headers.host, req.url]); res.end('x'); }));
    const p = await mk({}, { connect: () => net.connect({ host: '127.0.0.1', port: up }), resolve: async () => [PUBLIC] });
    await getRaw(p.port, 'http://site.example');
    await getRaw(p.port, 'http://site.example?q=1');
    assert.deepEqual(seen, [['site.example', '/'], ['site.example', '/?q=1']]);
    await p.close();
  });

  test('an upstream that closes without answering is an error decision', async () => {
    const dead = await listen(net.createServer((s) => s.destroy()));
    const p = await mk({}, {}, (c) => ({ ...c, allowlist: [{ name: 'fx.example', port: dead, address: '127.0.0.1' }] }));
    const r = await getRaw(p.port, `http://fx.example:${dead}/`);
    assert.equal(status(r), 502);
    assert.equal((await take(p.port)).json.denials[0].decision, 'error');
    await p.close();
  });
});

// ---------------------------------------------------------------- limits

describe('limits', () => {
  const allow = (port) => (c) => ({ ...c, allowlist: [{ name: 'fx.example', port, address: '127.0.0.1' }] });

  test('connections beyond the cap get 503 and the slot buffer says limit', async () => {
    const echo = await echoServer();
    const p = await mk({ EGRESS_MAX_CONNECTIONS: '2' }, {}, allow(echo));
    const a = await tunnel(p.port, `fx.example:${echo}`);
    const b = await tunnel(p.port, `fx.example:${echo}`);
    assert.deepEqual([a.status, b.status], [200, 200]);
    const c = await connectRaw(p.port, `fx.example:${echo}`);
    assert.equal(status(c), 503);
    assert.equal(reasonOf(c), 'limit');
    assert.equal(status(await getRaw(p.port, `http://fx.example:${echo}/`)), 503);
    assert.deepEqual((await take(p.port)).json.denials.map((d) => d.reason), ['limit', 'limit']);
    a.sock.destroy();
    await new Promise((ok) => setTimeout(ok, 100));
    assert.equal((await tunnel(p.port, `fx.example:${echo}`)).status, 200); // a freed place is usable again
    b.sock.destroy();
    await p.close();
  });

  test('an idle tunnel is closed', async () => {
    const echo = await echoServer();
    const p = await mk({ EGRESS_IDLE_TIMEOUT_MS: '150' }, {}, allow(echo));
    const t = await tunnel(p.port, `fx.example:${echo}`);
    assert.equal(await closed(t.sock, 2000), true);
    await p.close();
  });

  test('a tunnel is closed at its maximum lifetime even when busy', async () => {
    const echo = await echoServer();
    const p = await mk({ EGRESS_MAX_LIFETIME_MS: '300' }, {}, allow(echo));
    const t = await tunnel(p.port, `fx.example:${echo}`);
    const tick = setInterval(() => t.sock.write('x'), 40);
    const t0 = Date.now();
    assert.equal(await closed(t.sock, 3000), true);
    clearInterval(tick);
    assert.ok(Date.now() - t0 < 2000);
    await p.close();
  });

  test('a tunnel is closed after the byte cap', async () => {
    const echo = await echoServer();
    const p = await mk({ EGRESS_MAX_TUNNEL_BYTES: '2000' }, {}, allow(echo));
    const t = await tunnel(p.port, `fx.example:${echo}`);
    const tick = setInterval(() => t.sock.write(Buffer.alloc(500, 1)), 10);
    assert.equal(await closed(t.sock, 3000), true);
    clearInterval(tick);
    await new Promise((ok) => setTimeout(ok, 100));
    const line = p.lines.find((l) => l.decision === 'allow');
    assert.ok(line.bytes_up + line.bytes_down >= 2000);
    assert.equal(p.proxy.inflight(), 0);
    await p.close();
  });

  test('a response larger than the byte cap is cut off', async () => {
    const up = await listen(http.createServer((req, res) => { res.setHeader('content-length', 100000); res.write(Buffer.alloc(100000, 65)); res.end(); }));
    const p = await mk({ EGRESS_MAX_TUNNEL_BYTES: '5000' }, {}, allow(up));
    const r = await getRaw(p.port, `http://fx.example:${up}/big`);
    assert.ok(body(r).length < 100000);
    await p.close();
  });

  test('the in-flight count returns to zero after refusals and closes', async () => {
    const p = await mk();
    await connectRaw(p.port, 'localhost:80');
    await getRaw(p.port, 'http://10.0.0.1/');
    assert.equal(p.proxy.inflight(), 0);
    await p.close();
  });
});

// ---------------------------------------------------------------- logging

describe('log lines are host-less', () => {
  test('no name, address, path or header text appears in any log line, and fields are the closed set', async () => {
    const echo = await echoServer();
    const up = await listen(http.createServer((req, res) => res.end('page')));
    const p = await mk({ EGRESS_SLOT_PORTS: '0,0' }, { resolve: async (n) => (n === 'rebound-zzz.example' ? ['10.9.8.7'] : n === 'gone-zzz.example' ? Promise.reject(new Error('lookup-secret')) : [PUBLIC]) },
      (c) => ({ ...c, allowlist: [{ name: 'fx-zzz.example', port: echo, address: '127.0.0.1' }, { name: 'web-zzz.example', port: up, address: '127.0.0.1' }] }));
    const t = await tunnel(p.ports[0], `fx-zzz.example:${echo}`);
    t.sock.write('payload-zzz');
    await nextData(t.sock);
    t.sock.destroy();
    await getRaw(p.ports[1], `http://web-zzz.example:${up}/path-zzz?q=token-zzz`, 'Cookie: session-zzz=1\r\nUser-Agent: agent-zzz\r\n');
    for (const a of ['10.9.8.7:443', 'secret-zzz.localhost:80', '[::1]:443', '2130706433:80', 'rebound-zzz.example:443', 'gone-zzz.example:443', 'x-zzz.example:25']) await connectRaw(p.ports[0], a);
    await getRaw(p.ports[1], 'http://169.254.169.254/latest/meta-data/');
    await new Promise((ok) => setTimeout(ok, 150));
    const text = p.lines.map((l) => JSON.stringify(l)).join('\n');
    for (const bad of ['zzz', '10.9.8.7', '127.0.0.1', '169.254', '2130706433', '::1', 'lookup-secret', 'localhost', 'example', 'meta-data']) assert.ok(!text.includes(bad), bad);
    const allowed = new Set(['event', 'slot', 'decision', 'reason', 'range_class', 'port_class', 'status', 'bytes_up', 'bytes_down', 'duration_ms']);
    for (const l of p.lines) {
      assert.ok(Object.keys(l).every((k) => allowed.has(k)), JSON.stringify(l));
      assert.ok(['allow', 'deny', 'error'].includes(l.decision));
      assert.ok([0, 1].includes(l.slot));
    }
    assert.ok(p.lines.some((l) => l.decision === 'allow') && p.lines.some((l) => l.decision === 'deny') && p.lines.some((l) => l.decision === 'error'));
    await p.close();
  });

  test('the process writes nothing but JSON lines to stdout and nothing to stderr while serving', async () => {
    const r = await new Promise((ok) => {
      const p = spawn(process.execPath, [SCRIPT], { env: { PATH: process.env.PATH, EGRESS_PROFILE: 'production', EGRESS_BLOCK_EXTRA_CIDRS: '10.80.0.0/16', EGRESS_LISTEN: '127.0.0.1:0' }, stdio: ['ignore', 'pipe', 'pipe'] });
      let out = '', err = '';
      p.stderr.on('data', (d) => (err += d));
      p.stdout.on('data', async (d) => {
        out += d;
        if (out.split('\n').length === 2) { // the start line is in
          const port = JSON.parse(out).ports[0];
          await connectRaw(port, 'secret-zzz.localhost:443');
          await connectRaw(port, '10.80.1.2:443');
          await new Promise((k) => setTimeout(k, 100));
          p.kill('SIGTERM');
        }
      });
      p.on('close', () => ok({ out, err }));
      setTimeout(() => p.kill('SIGKILL'), 5000).unref();
    });
    const lines = r.out.trim().split('\n').map((l) => JSON.parse(l));
    assert.equal(lines[0].event, 'start');
    assert.deepEqual(lines.slice(1).map((l) => [l.reason, l.range_class]), [['name-blocked', null], ['literal-blocked', 'private']]);
    assert.ok(!r.out.includes('zzz') && !r.out.includes('10.80.1.2'));
    assert.equal(r.err, '');
  });
});
