import { test } from 'node:test';
import assert from 'node:assert/strict';
import { createLogger, redact, LEVELS, DEFAULT_PATTERNS, type Sink } from '../src/index.ts';

function capture() {
  const lines: Array<[string, string]> = [];
  const sink = Object.fromEntries(
    LEVELS.map((level) => [level, (line: string) => lines.push([level, line])]),
  ) as unknown as Sink;
  return { sink, lines };
}

test('masks secrets in plain strings', () => {
  const { sink, lines } = capture();
  createLogger(['hunter2'], { console: sink }).log('password is hunter2!');
  assert.deepEqual(lines, [['log', 'password is [REDACTED]!']]);
});

test('every level writes to the matching console method', () => {
  const { sink, lines } = capture();
  const log = createLogger(['s3cr3t'], { console: sink });
  for (const level of LEVELS) log[level](level, 's3cr3t');
  assert.deepEqual(lines, LEVELS.map((level) => [level, `${level} [REDACTED]`]));
});

test('masks secrets inside objects, arrays and errors', () => {
  const log = createLogger(['hunter2']);
  const out = log.redact({ user: 'bob', pass: 'hunter2', list: ['hunter2'] }, new Error('hunter2 leaked'));
  assert.ok(!out.includes('hunter2'));
  assert.match(out, /pass: '\[REDACTED\]'/);
  assert.match(out, /Error: \[REDACTED\] leaked/);
});

test('masks escaped forms: JSON, util.inspect and URL encoding', () => {
  const secret = `a'b"c\\d/e f`;
  const log = createLogger([secret]);
  assert.equal(log.redact(JSON.stringify({ secret })), '{"secret":"[REDACTED]"}');
  assert.ok(!log.redact({ secret }).includes('b"c'));
  assert.equal(log.redact(`?q=${encodeURIComponent(secret)}`), '?q=[REDACTED]');
});

test('respects printf-style formatting like console.log', () => {
  assert.equal(createLogger(['tok3n']).redact('%s=%d', 'tok3n', 42), '[REDACTED]=42');
});

test('ignores empty, null and undefined secrets', () => {
  const log = createLogger([undefined, null, '', 'real']);
  assert.equal(log.redact('nothing undefined null here, real'), 'nothing undefined null here, [REDACTED]');
});

test('no secrets means output is untouched', () => {
  assert.equal(createLogger().redact('hello', { a: 1 }), "hello { a: 1 }");
});

test('longer overlapping secrets win', () => {
  const log = createLogger(['abcd', 'abcdefgh'], { mask: '*' });
  assert.equal(log.redact('abcdefgh abcd'), '* *');
});

test('regex metacharacters in secrets are literal', () => {
  const log = createLogger(['a.b*c(d)?[e]$^|']);
  assert.equal(log.redact('xa.b*c(d)?[e]$^|x aXbbc'), 'x[REDACTED]x aXbbc');
});

test('custom mask function receives the original secret', () => {
  const log = createLogger(['p@ss word'], { mask: (s) => `<${s.length} chars>` });
  assert.equal(log.redact('p@ss word', encodeURIComponent('p@ss word')), '<9 chars> <9 chars>');
});

test('numbers can be secrets', () => {
  assert.equal(createLogger([123456]).redact('pin', 123456), 'pin [REDACTED]');
});

test('add() registers secrets later and chains', () => {
  const log = createLogger(['first']);
  assert.equal(log.add('second').add(undefined, 'third'), log);
  assert.equal(log.redact('first second third'), '[REDACTED] [REDACTED] [REDACTED]');
});

test('install() routes the global console and restores it', () => {
  const { sink, lines } = capture();
  const original = console.log;
  const restore = createLogger(['hunter2'], { console: sink }).install();
  try {
    console.log('global', 'hunter2');
  } finally {
    restore();
  }
  assert.equal(console.log, original);
  assert.deepEqual(lines, [['log', 'global [REDACTED]']]);
});

test('install() does not recurse when writing to the global console', (t) => {
  const written: string[] = [];
  t.mock.method(console, 'log', (line: string) => written.push(line));
  const restore = createLogger(['hunter2']).install();
  try {
    console.log('hunter2');
  } finally {
    restore();
  }
  assert.deepEqual(written, ['[REDACTED]']);
});

test('redact() helper works standalone', () => {
  assert.equal(redact('id=abcd1234', ['abcd1234']), 'id=[REDACTED]');
  assert.equal(redact('id=abcd1234', ['abcd1234'], '***'), 'id=***');
});

// ─── Short secrets ──────────────────────────────────────────────────────────

test('short secrets throw, at creation and in add()', () => {
  assert.throws(() => createLogger(['abc']), RangeError);
  assert.throws(() => createLogger([7]), RangeError);
  const log = createLogger(['long-enough']);
  assert.throws(() => log.add('good-one', 'no'), /at least 4 characters/);
  assert.equal(log.redact('good-one'), 'good-one', 'a failed add() registers nothing');
});

// ─── Sensitive keys ─────────────────────────────────────────────────────────

test('masks values of sensitive fields in objects without listing them', () => {
  const out = redact({
    user: 'bob',
    dbPassword: 'correct horse',
    'x-api-key': 'k-12345',
    refresh_token: 'rt',
    auth: { user: 'u', pass: 'p' },
    maxTokens: 1024,
    author: 'ada',
  });
  assert.match(out, /user: 'bob'/);
  assert.match(out, /dbPassword: '\[REDACTED\]'/);
  assert.match(out, /'x-api-key': '\[REDACTED\]'/);
  assert.match(out, /refresh_token: '\[REDACTED\]'/);
  assert.match(out, /auth: '\[REDACTED\]'/);
  assert.match(out, /maxTokens: 1024/);
  assert.match(out, /author: 'ada'/);
});

test('keeps missing or boolean sensitive values visible for debugging', () => {
  assert.equal(redact({ password: undefined, token: null, secret: '', auth: true }),
    "{ password: undefined, token: null, secret: '', auth: true }");
});

test('masks sensitive fields in JSON, query strings and env lines', () => {
  assert.equal(redact('{"password":"p w","ok":1}'), '{"password":"[REDACTED]","ok":1}');
  assert.equal(redact('GET https://x.io/?token=abc123&page=2'), 'GET https://x.io/?token=[REDACTED]&page=2');
  assert.equal(redact('DB_PASSWORD=zz9 PORT=5432'), 'DB_PASSWORD=[REDACTED] PORT=5432');
});

test('masks sensitive fields on errors and keeps the stack', () => {
  const error = Object.assign(new Error('request failed'), {
    config: { headers: { Authorization: 'Basic dXNlcjpwYXNz' } },
  });
  const out = redact(error);
  assert.match(out, /Error: request failed\n\s+at /);
  assert.ok(!out.includes('dXNlcjpwYXNz'));
});

test('does not touch the logged object', () => {
  const config = { password: 'hunter2' };
  redact(config);
  assert.equal(config.password, 'hunter2');
});

test('handles circular structures and does not invoke getters', () => {
  const node: Record<string, unknown> = { token: 'abcdef' };
  node['self'] = node;
  Object.defineProperty(node, 'lazy', { enumerable: true, get: () => { throw new Error('called'); } });
  const out = redact(node);
  assert.match(out, /token: '\[REDACTED\]'/);
  assert.match(out, /\[Circular \*1\]/);
});

test('sensitiveKeys can be customised or disabled', () => {
  const custom = createLogger([], { sensitiveKeys: ['pin', /^ssn$/i] });
  assert.equal(custom.redact({ cardPin: 1234, SSN: 'x', password: 'shown' }),
    "{ cardPin: '[REDACTED]', SSN: '[REDACTED]', password: 'shown' }");
  assert.equal(createLogger([], { sensitiveKeys: false }).redact({ password: 'shown' }), "{ password: 'shown' }");
});

// ─── Known token patterns ───────────────────────────────────────────────────

test('masks well-known token formats', () => {
  const samples = [
    'AKIAIOSFODNN7EXAMPLE',
    `ghp_${'a'.repeat(36)}`,
    `github_pat_${'b'.repeat(30)}`,
    `sk_live_${'c'.repeat(24)}`,
    'xoxb-1234567890-abcdef',
    `AIza${'d'.repeat(35)}`,
    `sk-ant-api03-${'e'.repeat(40)}`,
    `sk-proj-${'f'.repeat(40)}`,
    'eyJhbGciOiJIUzI1NiJ9.eyJzdWIiOiIxMjM0In0.c2lnbmF0dXJl',
  ];
  for (const sample of samples) assert.equal(redact(`got ${sample}.`), 'got [REDACTED].', sample);
});

test('masks only the credential after Bearer/Basic, and leaves prose alone', () => {
  assert.equal(redact('Bearer abc.def123456'), 'Bearer [REDACTED]');
  assert.equal(redact('use Basic authentication or Bearer tokens'), 'use Basic authentication or Bearer tokens');
});

test('masks PEM private keys, also with escaped newlines', () => {
  const pem = '-----BEGIN RSA PRIVATE KEY-----\nMIIEow\nIBAAK\n-----END RSA PRIVATE KEY-----';
  assert.equal(redact(pem), '[REDACTED]');
  assert.match(redact({ cert: pem }), /cert: '\[REDACTED\]'/);
});

test('patterns can be extended or disabled', () => {
  const log = createLogger([], { patterns: [...DEFAULT_PATTERNS, /\bacme_[a-z0-9]{8}\b/] });
  assert.equal(log.redact('acme_abcd1234'), '[REDACTED]');
  assert.equal(createLogger([], { patterns: false }).redact('AKIAIOSFODNN7EXAMPLE'), 'AKIAIOSFODNN7EXAMPLE');
});

test('mask function sees the original value for every detector', () => {
  const seen: string[] = [];
  const log = createLogger(['listed-secret'], { mask: (s) => (seen.push(s), '#') });
  log.redact('listed-secret', { password: 'from-key' }, 'AKIAIOSFODNN7EXAMPLE');
  assert.deepEqual(seen.sort(), ['AKIAIOSFODNN7EXAMPLE', 'from-key', 'listed-secret']);
});

test('ordinary text is left alone', () => {
  const line = 'time 12:30, ratio a=b, count: 5, user=ada, url=https://x.io/a?page=2';
  assert.equal(redact(line), line);
});
