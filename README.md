# ts-redacted-logger

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
- **Safe with missing env vars**: `undefined`, `null` and `''` are ignored, so pass `process.env.X` straight in.

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

| option    | type                                     | default          |
| --------- | ---------------------------------------- | ---------------- |
| `mask`    | `string \| (secret: string) => string`   | `'[REDACTED]'`   |
| `console` | any object with `log/info/warn/error/debug` | global `console` |

Returns a logger with:

| method            | what it does                                                      |
| ----------------- | ----------------------------------------------------------------- |
| `log/info/warn/error/debug(...args)` | print, redacted                                 |
| `redact(...args)` | return the redacted string instead of printing it                 |
| `add(...secrets)` | register more secrets later (chainable)                           |
| `install()`       | redact the **global** `console` too; returns a `restore()` function |

### `redact(value, secrets, mask?)`

One-shot helper for a single value.

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

**Tokens you only get at runtime**

```ts
const { access_token } = await login();
log.add(access_token);
```

## Caveats

Redaction is exact-match on the strings you provide (plus the escaped forms above). It cannot catch a secret that has been transformed in other ways, e.g. base64 inside a `Basic` auth header. If you log those, add the transformed value too:

```ts
log.add(Buffer.from(`${user}:${pass}`).toString('base64'));
```

## Development

```bash
npm install
npm test        # node:test, runs the TypeScript sources directly
npm run build   # emits dist/
```

## License

MIT
