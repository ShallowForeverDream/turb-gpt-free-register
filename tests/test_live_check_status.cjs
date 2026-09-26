const assert = require('node:assert/strict');
const fs = require('node:fs');
const path = require('node:path');
const vm = require('node:vm');
const {test} = require('node:test');
const context = vm.createContext({});
vm.runInContext(fs.readFileSync(path.join(__dirname, '../webui/templates/live_check_status.html'), 'utf8'), context);

test('new blocked status and historical HTTP errors have a manual action', () => {
  for (const row of [
    {live_check_status: 'blocked', live_check_error_code: 'http_403'},
    {live_check_status: 'failed', live_check_error: 'HTTPError: HTTP Error 403:'},
    {live_check_status: 'failed', live_check_error: 'HTTP 429 Too Many Requests'},
  ]) assert.equal(context.liveCheckNeedsManualLogin(row), true);
  assert.match(context.liveCheckBlockedText({live_check_stage: 'login_preflight'}), /尚未发码/);
  assert.doesNotMatch(context.liveCheckBlockedText({live_check_stage: 'authentication'}), /尚未发码/);
});

test('transport and explicit account errors stay separate', () => {
  assert.equal(context.liveCheckNeedsManualLogin({live_check_status: 'failed', live_check_error: 'connection timeout'}), false);
  assert.equal(context.liveCheckNeedsManualLogin({live_check_status: 'deactivated', live_check_error: 'HTTP 403 account_deactivated'}), false);
});

test('workspace selection is not described as an access denial', () => {
  const row = {live_check_status: 'action_required', live_check_error_code: 'workspace_selection_required'};
  assert.equal(context.liveCheckNeedsManualLogin(row), true);
  assert.match(context.liveCheckBlockedText(row), /工作区选择/);
  assert.match(context.liveCheckBlockedText(row), /AT 尚未获取/);
  assert.doesNotMatch(context.liveCheckBlockedText(row), /被拒绝|限流|尚未发码/);
});
