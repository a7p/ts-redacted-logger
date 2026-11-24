// ESM usage:  node examples/basic.mjs
import { createLogger } from 'ts-redacted-logger';

const log = createLogger(['hunter2', 'sk_live_abc123']);

log.info('connecting as admin with password hunter2');
log.warn({ apiKey: 'sk_live_abc123', region: 'eu-west-1' });
log.error(new Error('auth failed for sk_live_abc123'));
