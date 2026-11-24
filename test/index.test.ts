import { test } from 'node:test';
import assert from 'node:assert/strict';
import { createLogger, redact, LEVELS, type Sink } from '../src/index.ts';

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
  assert.equal(createLogger(['tok']).redact('%s=%d', 'tok', 42), '[REDACTED]=42');
});

test('ignores empty, null and undefined secrets', () => {
  const log = createLogger([undefined, null, '', 'real']);
  assert.equal(log.redact('nothing undefined null here, real'), 'nothing undefined null here, [REDACTED]');
});

test('no secrets means output is untouched', () => {
  assert.equal(createLogger().redact('hello', { a: 1 }), "hello { a: 1 }");
});

test('longer overlapping secrets win', () => {
  const log = createLogger(['abc', 'abcdef'], { mask: '*' });
  assert.equal(log.redact('abcdef abc'), '* *');
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
  const log = createLogger(['one']);
  assert.equal(log.add('two').add(undefined, 'three'), log);
  assert.equal(log.redact('one two three'), '[REDACTED] [REDACTED] [REDACTED]');
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
  assert.equal(redact('token=abc', ['abc']), 'token=[REDACTED]');
  assert.equal(redact('token=abc', ['abc'], '***'), 'token=***');
});
