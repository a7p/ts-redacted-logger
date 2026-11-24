// CommonJS usage:  node examples/basic.cjs
const { createLogger } = require('ts-redacted-logger');

const log = createLogger(['hunter2'], { mask: (s) => '*'.repeat(s.length) });
const restore = log.install(); // now plain console.log is redacted too

console.log('db url: postgres://admin:hunter2@localhost/app');
restore();
