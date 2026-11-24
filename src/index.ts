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

/** Anything that can be handed to the logger as a secret. Empty values are ignored. */
export type Secret = string | number | bigint | null | undefined;

/** Replacement text, or a function that derives it from the secret being hidden. */
export type Mask = string | ((secret: string) => string);

/** The console methods the logger wraps. */
export const LEVELS = ['log', 'info', 'warn', 'error', 'debug'] as const;

export type Level = (typeof LEVELS)[number];

/** The minimal console shape the logger writes to. `globalThis.console` fits. */
export type Sink = Pick<Console, Level>;

export interface LoggerOptions {
  /** What a secret is replaced with. Defaults to `"[REDACTED]"`. */
  mask?: Mask;
  /** Where redacted output goes. Defaults to the global `console`. */
  console?: Sink;
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

  /** Registers more secrets after creation, e.g. a freshly issued token. */
  add(...secrets: Secret[]): this;

  /**
   * Routes the global `console.log/info/warn/error/debug` through this logger,
   * so third-party code is redacted too. Returns a function that restores the
   * original console.
   */
  install(): () => void;
}

export const DEFAULT_MASK = '[REDACTED]';

/**
 * Creates a logger that masks every given secret before anything is written.
 *
 * @param secrets Credentials to hide. `undefined`, `null` and empty strings are
 *                skipped, so `process.env.MAYBE_SET` can be passed directly.
 * @param options Optional mask and output target.
 */
export function createLogger(
  secrets: Iterable<Secret> = [],
  options: LoggerOptions = {},
): RedactedLogger {
  const mask = options.mask ?? DEFAULT_MASK;
  const known = new Set<string>();
  let matcher: Matcher | undefined;

  // Capture the sink's methods now, so `install()` can never make us call ourselves.
  const sink = options.console ?? globalThis.console;
  const write = Object.fromEntries(
    LEVELS.map((level) => [level, sink[level].bind(sink)]),
  ) as Record<Level, (line: string) => void>;

  const add = (values: Iterable<Secret>): void => {
    let changed = false;
    for (const value of values) {
      if (value === null || value === undefined) continue;
      const secret = String(value);
      if (secret.length === 0 || known.has(secret)) continue;
      known.add(secret);
      changed = true;
    }
    if (changed) matcher = buildMatcher(known);
  };

  const redactText = (text: string): string => {
    if (!matcher) return text;
    const { pattern, origin } = matcher;
    return text.replace(pattern, (found) =>
      typeof mask === 'string' ? mask : mask(origin.get(found) ?? found),
    );
  };

  add(secrets);

  const logger: RedactedLogger = {
    log: (...args) => write.log(logger.redact(...args)),
    info: (...args) => write.info(logger.redact(...args)),
    warn: (...args) => write.warn(logger.redact(...args)),
    error: (...args) => write.error(logger.redact(...args)),
    debug: (...args) => write.debug(logger.redact(...args)),

    redact: (...args) => redactText(format(...args)),

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
 * One-shot helper: redact a single string (or anything printable) without
 * creating a logger.
 */
export function redact(value: unknown, secrets: Iterable<Secret>, mask: Mask = DEFAULT_MASK): string {
  return createLogger(secrets, { mask }).redact(value);
}

/**
 * Builds one regular expression that matches every secret, plus the forms a
 * secret takes once it has been serialised: escaped inside JSON, escaped by
 * `util.inspect` (used for objects in `console.log`), and URL-encoded.
 * Longest variants come first, so overlapping secrets are masked whole.
 */
interface Matcher {
  pattern: RegExp;
  /** Maps every matchable variant back to the secret it came from. */
  origin: Map<string, string>;
}

function buildMatcher(secrets: Iterable<string>): Matcher {
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

function escapeRegExp(text: string): string {
  return text.replace(/[.*+?^${}()|[\]\\\/-]/g, '\\$&');
}
