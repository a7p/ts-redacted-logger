/**
 * ts-redacted-logger
 *
 * A tiny `console.log` wrapper that keeps your credentials out of your logs.
 *
 * ```ts
 * import { createLogger } from 'ts-redacted-logger';
 *
 * const log = createLogger([process.env.DB_PASSWORD, process.env.API_KEY]);
 * log.info('connecting with', process.env.DB_PASSWORD);
 * // → connecting with [REDACTED]
 * ```
 *
 * @module
 */

import { format, inspect } from 'node:util';

/** Anything that can be handed to the logger as a secret. `null`/`undefined`/`''` are ignored. */
export type Secret = string | number | bigint | null | undefined;

/** Replacement text, or a function that derives it from the value being hidden. */
export type Mask = string | ((secret: string) => string);

/** The console methods the logger wraps. */
export const LEVELS = ['log', 'info', 'warn', 'error', 'debug'] as const;

export type Level = (typeof LEVELS)[number];

/** The minimal console shape the logger writes to. `globalThis.console` fits. */
export type Sink = Pick<Console, Level>;

/** Secrets shorter than this are rejected: they would shred every log line. */
export const MIN_SECRET_LENGTH = 4;

export const DEFAULT_MASK = '[REDACTED]';

/**
 * Field names whose values are always masked. A field matches when its name,
 * lower-cased and stripped of `-`, `_` and `.`, *ends with* one of these, so
 * `dbPassword`, `x-api-key` and `refresh_token` match while `maxTokens` and
 * `author` do not.
 */
export const DEFAULT_SENSITIVE_KEYS: readonly string[] = [
  'password', 'passwd', 'pwd', 'passphrase',
  'secret', 'secrets', 'secretkey',
  'token', 'apikey', 'accesskey', 'privatekey',
  'credential', 'credentials',
  'auth', 'authorization',
  'cookie', 'setcookie', 'sessionid', 'signature',
];

/**
 * Well-known credential formats, masked wherever they appear. When a pattern
 * has a named group `secret`, only that group is masked (e.g. the token after
 * `Bearer `), otherwise the whole match is.
 */
export const DEFAULT_PATTERNS: readonly RegExp[] = [
  // PEM private keys, raw or with escaped newlines.
  /-----BEGIN [A-Z ]*PRIVATE KEY-----[\s\S]*?-----END [A-Z ]*PRIVATE KEY-----/,
  // JSON Web Tokens.
  /\beyJ[\w-]{5,}\.eyJ[\w-]{5,}\.[\w-]+/,
  // HTTP Authorization schemes. The lookahead keeps prose like "Basic authentication" intact.
  /\b(?:Bearer|Basic|Token)\s+(?<secret>(?=[\w.~+/=-]*[\d+/=])[\w.~+/-]{8,}=*)/,
  // AWS access key IDs.
  /\b(?:AKIA|ASIA)[0-9A-Z]{16}\b/,
  // GitHub tokens.
  /\bgh[pousr]_[A-Za-z0-9]{36,}\b/,
  /\bgithub_pat_\w{22,}/,
  // Stripe keys.
  /\b[rs]k_(?:live|test)_[A-Za-z0-9]{16,}\b/,
  // Slack tokens.
  /\bxox[abeoprs]-[A-Za-z0-9-]{10,}/,
  // Google API keys.
  /\bAIza[\w-]{35}\b/,
  // Anthropic and OpenAI keys.
  /\bsk-ant-[\w-]{20,}/,
  /\bsk-(?:proj-|svcacct-)?[A-Za-z0-9_-]{20,}/,
];

export interface LoggerOptions {
  /** What a secret is replaced with. Defaults to `"[REDACTED]"`. */
  mask?: Mask;
  /** Where redacted output goes. Defaults to the global `console`. */
  console?: Sink;
  /**
   * Field names whose values are masked even if not listed as secrets.
   * Strings match the end of the normalised name (see {@link DEFAULT_SENSITIVE_KEYS}),
   * RegExps are tested against the raw name. `false` disables this.
   * Defaults to {@link DEFAULT_SENSITIVE_KEYS}.
   */
  sensitiveKeys?: ReadonlyArray<string | RegExp> | false;
  /**
   * Credential formats masked wherever they appear. `false` disables this.
   * Defaults to {@link DEFAULT_PATTERNS}; spread it to add your own.
   */
  patterns?: readonly RegExp[] | false;
}

export interface RedactedLogger {
  /** Like `console.log`, but with every secret masked. */
  log(...args: unknown[]): void;
  /** Like `console.info`, but with every secret masked. */
  info(...args: unknown[]): void;
  /** Like `console.warn`, but with every secret masked. */
  warn(...args: unknown[]): void;
  /** Like `console.error`, but with every secret masked. */
  error(...args: unknown[]): void;
  /** Like `console.debug`, but with every secret masked. */
  debug(...args: unknown[]): void;

  /**
   * Formats the arguments exactly like `console.log` would and returns the
   * redacted string without printing it.
   */
  redact(...args: unknown[]): string;

  /**
   * Registers more secrets after creation, e.g. a freshly issued token.
   * @throws {RangeError} if a secret is shorter than {@link MIN_SECRET_LENGTH}.
   */
  add(...secrets: Secret[]): this;

  /**
   * Routes the global `console.log/info/warn/error/debug` through this logger,
   * so third-party code is redacted too. Returns a function that restores the
   * original console.
   */
  install(): () => void;
}

/**
 * Creates a logger that masks secrets before anything is written.
 *
 * @param secrets Credentials to hide. `undefined`, `null` and empty strings are
 *                skipped, so `process.env.MAYBE_SET` can be passed directly.
 * @param options Mask, output target, and the automatic detectors.
 * @throws {RangeError} if a secret is shorter than {@link MIN_SECRET_LENGTH}.
 */
export function createLogger(
  secrets: Iterable<Secret> = [],
  options: LoggerOptions = {},
): RedactedLogger {
  const mask = options.mask ?? DEFAULT_MASK;
  const isSensitiveKey = keyMatcher(options.sensitiveKeys ?? DEFAULT_SENSITIVE_KEYS);
  const patterns = (options.patterns ?? DEFAULT_PATTERNS) || [];
  const scanners = patterns.map((p) => new RegExp(p.source, withFlags(p.flags, 'gd')));

  const known = new Set<string>();
  let exact: ExactMatcher | undefined;

  // Capture the sink's methods now, so `install()` can never make us call ourselves.
  const sink = options.console ?? globalThis.console;
  const write = Object.fromEntries(
    LEVELS.map((level) => [level, sink[level].bind(sink)]),
  ) as Record<Level, (line: string) => void>;

  const add = (values: Iterable<Secret>): void => {
    const fresh: string[] = [];
    for (const value of values) {
      if (value === null || value === undefined) continue;
      const secret = String(value);
      if (secret.length === 0 || known.has(secret)) continue;
      if (secret.length < MIN_SECRET_LENGTH) {
        throw new RangeError(
          `ts-redacted-logger: refusing a secret of ${secret.length} character(s); ` +
            `secrets must be at least ${MIN_SECRET_LENGTH} characters long, ` +
            `otherwise ordinary log text would be masked. Check your configuration.`,
        );
      }
      fresh.push(secret);
    }
    // Validate everything before mutating, so a bad call changes nothing.
    for (const secret of fresh) known.add(secret);
    if (fresh.length > 0) exact = buildExactMatcher(known);
  };

  const redact = (...args: unknown[]): string => {
    const vault = new Vault();
    const scrubbed = isSensitiveKey ? args.map((arg) => scrubKeys(arg, isSensitiveKey, vault)) : args;
    let text = format(...scrubbed);

    if (exact) {
      const { pattern, origin } = exact;
      text = text.replace(pattern, (found) => vault.hide(origin.get(found) ?? found));
    }
    for (const scanner of scanners) {
      text = replaceSpans(text, scanner, (match) => {
        const span = match.indices?.groups?.['secret'] ?? match.indices?.[0];
        return span ? [span] : [];
      }, vault);
    }
    if (isSensitiveKey) {
      text = replaceSpans(text, KEY_VALUE, (match) => {
        const name = match.groups?.['name'] ?? '';
        const value = match.groups?.['value'] ?? '';
        const span = match.indices?.groups?.['value'];
        if (!span || !isSensitiveKey(name) || isHarmless(value)) return [];
        const quoted = /^["'`]/.test(value);
        return [quoted ? [span[0] + 1, span[1] - 1] : span];
      }, vault);
    }
    return vault.reveal(text, mask);
  };

  add(secrets);

  const logger: RedactedLogger = {
    log: (...args) => write.log(redact(...args)),
    info: (...args) => write.info(redact(...args)),
    warn: (...args) => write.warn(redact(...args)),
    error: (...args) => write.error(redact(...args)),
    debug: (...args) => write.debug(redact(...args)),

    redact,

    add(...more) {
      add(more);
      return this;
    },

    install() {
      const target = globalThis.console;
      const originals = Object.fromEntries(
        LEVELS.map((level) => [level, target[level]]),
      ) as Record<Level, Console[Level]>;
      for (const level of LEVELS) target[level] = logger[level];
      return () => {
        for (const level of LEVELS) target[level] = originals[level];
      };
    },
  };

  return logger;
}

/**
 * One-shot helper: redact a single value without keeping a logger around.
 * The automatic detectors are on, as with {@link createLogger}.
 */
export function redact(value: unknown, secrets: Iterable<Secret> = [], mask: Mask = DEFAULT_MASK): string {
  return createLogger(secrets, { mask }).redact(value);
}

// ─── Internals ──────────────────────────────────────────────────────────────

/**
 * Every redaction first becomes a placeholder made of private-use characters,
 * so later passes can't match inside an earlier mask, and the mask function
 * always sees the original value. Placeholders are swapped for masks last.
 */
class Vault {
  static readonly OPEN = '';
  static readonly CLOSE = '';
  static readonly TOKEN = /([-]+)/g;

  private readonly values: string[] = [];

  hide(value: string): string {
    let index = this.values.push(value) - 1;
    let digits = '';
    do {
      digits = String.fromCharCode(0xe100 + (index % 0x1000)) + digits;
      index = Math.floor(index / 0x1000);
    } while (index > 0);
    return Vault.OPEN + digits + Vault.CLOSE;
  }

  reveal(text: string, mask: Mask): string {
    if (this.values.length === 0) return text;
    return text.replace(Vault.TOKEN, (_, digits: string) => {
      let index = 0;
      for (const char of digits) index = index * 0x1000 + (char.charCodeAt(0) - 0xe100);
      const value = this.values[index] ?? '';
      return typeof mask === 'string' ? mask : mask(value);
    });
  }

  static touches(text: string): boolean {
    return text.includes(Vault.OPEN) || text.includes(Vault.CLOSE);
  }
}

interface ExactMatcher {
  pattern: RegExp;
  /** Maps every matchable variant back to the secret it came from. */
  origin: Map<string, string>;
}

/**
 * One regular expression for every secret, plus the forms a secret takes once
 * serialised: escaped inside JSON, escaped by `util.inspect` (used for objects
 * in `console.log`), and URL-encoded. Longest first, so overlaps mask whole.
 */
function buildExactMatcher(secrets: Iterable<string>): ExactMatcher {
  const origin = new Map<string, string>();
  for (const secret of secrets) {
    for (const variant of [
      secret,
      JSON.stringify(secret).slice(1, -1),
      inspect(secret).slice(1, -1),
      encodeURIComponent(secret),
    ]) {
      if (variant.length > 0 && !origin.has(variant)) origin.set(variant, secret);
    }
  }
  const source = [...origin.keys()]
    .sort((a, b) => b.length - a.length)
    .map(escapeRegExp)
    .join('|');
  return { pattern: new RegExp(source, 'g'), origin };
}

/**
 * `name: value`, `"name":"value"`, `name=value` in text: JSON, `util.inspect`
 * output, query strings, headers and env-style lines.
 */
// The value sits in a lookahead so it is not consumed: pairs nested inside a
// harmless value (`url=https://x/?token=…`) are still found.
const KEY_VALUE =
  /(?<name>[A-Za-z_$][\w$.-]*)["'`]?[ \t]*[:=][ \t]*(?=(?<value>"(?:[^"\\\n]|\\.)*"|'(?:[^'\\\n]|\\.)*'|`(?:[^`\\]|\\.)*`|[^\s"'`&,;)}\]]+))/dg;

/** Values worth keeping visible: they reveal configuration, not credentials. */
function isHarmless(value: string): boolean {
  return /^(?:["'`]{2}|null|undefined|true|false|\[Object\]|\[Array\]|\[Getter(?:\/Setter)?\]|\[Circular \*\d+\])$/.test(value);
}

type KeyTest = (name: string) => boolean;

function keyMatcher(keys: ReadonlyArray<string | RegExp> | false): KeyTest | undefined {
  if (!keys || keys.length === 0) return undefined;
  const suffixes = keys.filter((k): k is string => typeof k === 'string').map(normaliseKey);
  const regexps = keys
    .filter((k): k is RegExp => k instanceof RegExp)
    .map((r) => new RegExp(r.source, r.flags.replace(/[gy]/g, '')));
  return (name) => {
    const normalised = normaliseKey(name);
    return suffixes.some((s) => normalised.endsWith(s)) || regexps.some((r) => r.test(name));
  };
}

function normaliseKey(name: string): string {
  return name.toLowerCase().replace(/[-_.\s]/g, '');
}

/**
 * Returns a copy of plain objects, arrays and errors in which the values of
 * sensitive fields are replaced by placeholders. Anything else is returned
 * untouched so `util.format` prints it as usual. Getters are never invoked.
 */
function scrubKeys(value: unknown, isSensitiveKey: KeyTest, vault: Vault, seen = new WeakMap<object, unknown>()): unknown {
  if (value === null || typeof value !== 'object') return value;
  const proto: unknown = Object.getPrototypeOf(value);
  const cloneable = Array.isArray(value) || value instanceof Error || proto === Object.prototype || proto === null;
  if (!cloneable) return value;
  if (seen.has(value)) return seen.get(value);

  const copy: object = Array.isArray(value) ? [] : Object.create(proto as object | null);
  seen.set(value, copy);
  const descriptors = Object.getOwnPropertyDescriptors(value) as Record<PropertyKey, PropertyDescriptor>;
  for (const key of Reflect.ownKeys(descriptors)) {
    const descriptor = descriptors[key];
    if (!descriptor || !('value' in descriptor)) continue;
    const inner: unknown = descriptor.value;
    descriptor.value =
      typeof key === 'string' && isSensitiveKey(key) && !isHarmlessValue(inner)
        ? vault.hide(typeof inner === 'string' ? inner : inspect(inner))
        : scrubKeys(inner, isSensitiveKey, vault, seen);
  }
  // `stack` may be an accessor bound to the original error; pin its text.
  if (value instanceof Error) descriptors['stack'] = { value: value.stack, writable: true, configurable: true, enumerable: false };
  Object.defineProperties(copy, descriptors);
  return copy;
}

function isHarmlessValue(value: unknown): boolean {
  return value === null || value === undefined || value === '' || typeof value === 'boolean';
}

type Span = [number, number];

/** Replaces the spans `pick` returns for each match with vault placeholders. */
function replaceSpans(text: string, pattern: RegExp, pick: (match: RegExpExecArray) => Span[], vault: Vault): string {
  let out = '';
  let cursor = 0;
  for (const match of text.matchAll(pattern) as IterableIterator<RegExpExecArray>) {
    for (const [start, end] of pick(match)) {
      if (start < cursor || end <= start) continue;
      const secret = text.slice(start, end);
      if (Vault.touches(secret)) continue;
      out += text.slice(cursor, start) + vault.hide(secret);
      cursor = end;
    }
  }
  return out + text.slice(cursor);
}

function withFlags(flags: string, required: string): string {
  let result = flags.replace(/y/g, '');
  for (const flag of required) if (!result.includes(flag)) result += flag;
  return result;
}

function escapeRegExp(text: string): string {
  return text.replace(/[.*+?^${}()|[\]\\\/-]/g, '\\$&');
}
