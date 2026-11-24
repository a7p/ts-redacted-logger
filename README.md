# ts-redacted-logger

[![CI](https://github.com/a7p/ts-redacted-logger/actions/workflows/ci.yml/badge.svg)](https://github.com/a7p/ts-redacted-logger/actions/workflows/ci.yml)

> A tiny `console.log` wrapper that keeps your credentials out of your logs.

Give it your secrets once. Log like you always do. They never reach the output.

```ts
import { createLogger } from 'ts-redacted-logger';

const log = createLogger([process.env.DB_PASSWORD, process.env.API_KEY]);

log.info('connecting with', process.env.DB_PASSWORD);
// connecting with [REDACTED]

log.warn({ apiKey: process.env.API_KEY, region: 'eu-west-1' });
// { apiKey: '[REDACTED]', region: 'eu-west-1' }
```

- **Zero dependencies**, written in TypeScript, ships its own types.
- **Drop-in**: `log`, `info`, `warn`, `error`, `debug` behave exactly like `console`, including `%s`/`%d` formatting, objects and errors.
- **Catches serialised forms**: secrets are also masked when they appear JSON-escaped, `util.inspect`-escaped or URL-encoded (`?token=…`, `postgres://user:pa%24%24@…`).
- **Finds what you forgot to list**: values of fields like `password`, `apiKey`, `authToken` or `Authorization` are masked automatically, in objects, JSON, query strings and `KEY=value` lines.
- **Knows common token formats**: JWTs, AWS, GitHub, Stripe, Slack, Google, OpenAI and Anthropic keys, `Bearer`/`Basic` credentials and PEM private keys.
- **Safe with missing env vars**: `undefined`, `null` and `''` are ignored, so pass `process.env.X` straight in.
- **Fails loudly on bad config**: a secret shorter than 4 characters throws, instead of quietly masking every `a` in your logs.

## Install

```bash
npm install ts-redacted-logger
```

Requires Node.js 24+. Works with both `import` and `require`:

```js
const { createLogger } = require('ts-redacted-logger');
```

## API

### `createLogger(secrets, options?)`

| option          | type                                        | default                  |
| --------------- | ------------------------------------------- | ------------------------ |
| `mask`          | `string \| (secret: string) => string`      | `'[REDACTED]'`           |
| `console`       | any object with `log/info/warn/error/debug` | global `console`         |
| `sensitiveKeys` | `(string \| RegExp)[] \| false`              | `DEFAULT_SENSITIVE_KEYS` |
| `patterns`      | `RegExp[] \| false`                          | `DEFAULT_PATTERNS`       |

Throws a `RangeError` if a secret is shorter than 4 characters.

Returns a logger with:

| method            | what it does                                                      |
| ----------------- | ----------------------------------------------------------------- |
| `log/info/warn/error/debug(...args)` | print, redacted                                 |
| `redact(...args)` | return the redacted string instead of printing it                 |
| `add(...secrets)` | register more secrets later (chainable)                           |
| `install()`       | redact the **global** `console` too; returns a `restore()` function |

### `redact(value, secrets?, mask?)`

One-shot helper for a single value.

## What gets masked

1. **Your secrets**, exactly, plus their JSON-escaped, `util.inspect`-escaped and URL-encoded forms.
2. **Sensitive fields.** A field matches when its name, lower-cased and without `-`, `_` and `.`, *ends with* one of `DEFAULT_SENSITIVE_KEYS` (`password`, `secret`, `token`, `apikey`, `auth`, `cookie`, …). So `dbPassword`, `x-api-key` and `refresh_token` are masked; `maxTokens` and `author` are not. Values that are `undefined`, `null`, `''` or a boolean stay visible, so you can still see that a setting is missing.
3. **Known token formats** from `DEFAULT_PATTERNS`. If a pattern has a named group `secret`, only that part is masked (`Bearer [REDACTED]`).

```ts
log.info({ user: 'ada', password: 'correct horse', maxTokens: 1024 });
// { user: 'ada', password: '[REDACTED]', maxTokens: 1024 }

log.info('GET https://api.example.com/?token=abc123&page=2');
// GET https://api.example.com/?token=[REDACTED]&page=2
```

The objects you log are never modified, and getters are never invoked.

## Recipes

**Redact everything, including third-party libraries**

```ts
createLogger([process.env.DB_PASSWORD]).install();
console.log(process.env.DB_PASSWORD); // [REDACTED]
```

**Show how long the secret was**

```ts
createLogger(secrets, { mask: (s) => '*'.repeat(s.length) });
```

**Your own field names and token formats**

```ts
import { createLogger, DEFAULT_SENSITIVE_KEYS, DEFAULT_PATTERNS } from 'ts-redacted-logger';

createLogger(secrets, {
  sensitiveKeys: [...DEFAULT_SENSITIVE_KEYS, 'pin', /^ssn$/i],
  patterns: [...DEFAULT_PATTERNS, /\bacme_[a-z0-9]{32}\b/],
});
```

Pass `false` to switch either detector off.

**Tokens you only get at runtime**

```ts
const { access_token } = await login();
log.add(access_token);
```

## Caveats

The automatic detectors are a safety net, not a guarantee: a credential with no telling field name and no known format is only caught if you list it. Listed secrets are matched exactly (plus the escaped forms above), so a secret transformed in other ways, e.g. base64-encoded, needs its transformed value listed too:

```ts
log.add(Buffer.from(`${user}:${pass}`).toString('base64'));
```

## Development

```bash
npm install
npm test        # node:test, runs the TypeScript sources directly
npm run build   # emits dist/
```

## Releasing

1. Bump the version: `npm version patch` (or `minor` / `major`), then push the commit and tag.
2. Create a GitHub release for that tag. The **Release** workflow tests the package and publishes it to npm with provenance.

Publishing uses npm trusted publishing, so no token is stored in GitHub. Set it up once on npmjs.com under the package's settings: *Trusted publishing → GitHub Actions*, repository `a7p/ts-redacted-logger`, workflow `release.yml`. The very first publish has to be done by hand (`npm publish`), because the package must exist before trusted publishing can be configured.

## License

MIT
