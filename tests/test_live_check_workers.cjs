const assert = require('node:assert/strict');
const fs = require('node:fs');
const path = require('node:path');
const vm = require('node:vm');
const {test} = require('node:test');

const html = fs.readFileSync(path.join(__dirname, '../webui/templates/index.html'), 'utf8');
const fn = html.slice(html.indexOf('async function checkSelectedLive('), html.indexOf('async function deleteAccount('));

test('bulk live check sends the account toolbar worker selection', async () => {
  const calls = [];
  const context = vm.createContext({
    ACCOUNT_SELECTED: new Set([1, 2, 3]), ACCOUNTS: [],
    getCodexBulkWorkers: () => 3,
    confirm: () => true, $: () => null,
    showToast: () => {}, openLiveLog: () => {},
    loadAccounts: async () => {}, loadSummary: () => {},
    api: async (url, options) => {
      calls.push({url, body: JSON.parse(options.body)});
      return {started_count: 3, workers: 3};
    },
  });
  vm.runInContext(fn, context);
  await context.checkSelectedLive();
  assert.equal(calls.length, 1);
  assert.equal(calls[0].url, '/api/accounts/check-live-bulk');
  assert.deepEqual(calls[0].body, {account_ids: [1, 2, 3], workers: 3});
});
