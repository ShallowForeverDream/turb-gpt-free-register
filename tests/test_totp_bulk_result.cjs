const assert = require('node:assert/strict');
const fs = require('node:fs');
const path = require('node:path');
const vm = require('node:vm');
const {test} = require('node:test');

const source = fs.readFileSync(path.join(__dirname, '../webui/templates/totp_bulk_result.html'), 'utf8');
const context = vm.createContext({});
vm.runInContext(source, context);

test('reports why email-only accounts were skipped', () => {
  const message = context.describeTotpBulkResult({
    started_count: 0,
    skipped: [1, 2, 3].map(id => ({id, reason: '缺少 access_token'})),
  });
  assert.match(message, /已入队 0 个/);
  assert.match(message, /跳过 3 个（缺少 access_token ×3）/);
  assert.match(message, /请先查活刷新 AT/);
});

test('groups distinct reasons without inventing an AT problem', () => {
  const message = context.describeTotpBulkResult({
    started_count: 1,
    skipped: [{reason: '该账号已经开启 2FA'}, {reason: '邮箱为空'}],
    busy_count: 1,
    failed_count: 1,
  });
  assert.match(message, /已入队 1 个/);
  assert.match(message, /该账号已经开启 2FA ×1/);
  assert.match(message, /邮箱为空 ×1/);
  assert.match(message, /进行中 1 个/);
  assert.match(message, /失败 1 个/);
  assert.doesNotMatch(message, /查活刷新 AT/);
});
