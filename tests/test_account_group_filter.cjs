const assert = require('node:assert/strict');
const fs = require('node:fs');
const path = require('node:path');
const vm = require('node:vm');
const {test} = require('node:test');
const dir = path.join(__dirname, '../webui/templates');
const shared = fs.readFileSync(path.join(dir, 'account_group_filter.html'), 'utf8');

function fixture(mode) {
  const filename = mode === 'modern' ? 'index.html' : 'index_legacy.html';
  const html = fs.readFileSync(path.join(dir, filename), 'utf8');
  const source = html.slice(html.indexOf('let accountsLoading = false;'), html.indexOf('function _codexCell('))
    .replace("{% include 'account_group_filter.html' %}", shared);
  const select = {value: '', options: [], replaceChildren(...options) { this.options = options; }};
  const fields = {
    [mode === 'modern' ? 'accountGroupFilterV2' : 'accountGroupFilter']: select,
    qAccounts: {value: ''}, qAccountsV2: {value: ''}, emailSuffixAccountsV2: {value: ''},
  };
  const calls = [], errors = [];
  const context = vm.createContext({AbortController,
    document: {getElementById: id => fields[id] || null, createElement: tag => ({tag})},
    $: selector => fields[selector.slice(1)] || null,
    SHOW_ARCHIVED_ACCOUNTS: false, SHOW_PLUS_ACCOUNTS_ONLY: false,
    SHOW_PLUS_TRIAL_ACCOUNTS_ONLY: false, SHOW_FREE_ACCOUNTS_ONLY: false,
    PAGERS: {accounts: {page: 1, size: 20}}, ACCOUNTS: [], ACCOUNTS_TOTAL: 0,
    api: (url, options) => new Promise(resolve => calls.push({url, options, resolve})),
    renderAccounts: () => {}, showToast: text => errors.push(text),
  });
  vm.runInContext(source, context);
  return {context, calls, errors, fields, select, html};
}

for (const mode of ['modern', 'legacy']) {
  test(`${mode}: group selector safely loads custom groups and keeps selection`, async () => {
    const f = fixture(mode);
    f.select.value = '已卖';
    const promise = f.context.loadAccountGroups();
    f.calls[0].resolve({groups: ['已卖', '备用', '已卖', '<img onerror="bad">']});
    await promise;
    assert.deepEqual(f.select.options.map(x => x.value), ['', '__ungrouped__', '已卖', '备用', '<img onerror="bad">']);
    assert.equal(f.select.value, '已卖');
    assert.ok(f.select.options.every(x => x.tag === 'option'));
    assert.equal(f.select.options.at(-1).textContent, '<img onerror="bad">');
    assert.match(f.html, /include 'account_table_header.html'/);
  });

  test(`${mode}: account list and background poll send the same group`, async () => {
    const f = fixture(mode);
    f.select.value = '已卖';
    const list = f.context.loadAccounts();
    assert.equal(new URL(f.calls[0].url, 'http://localhost').searchParams.get('group'), '已卖');
    f.calls[0].resolve({items: [], total: 0});
    await list;
    const poll = f.context.pollAccountPlanStatuses();
    assert.equal(new URL(f.calls[1].url, 'http://localhost').searchParams.get('group'), '已卖');
    f.calls[1].resolve({items: [], total: 0, revision: ''});
    await poll;
  });

  test(`${mode}: slow all-accounts response cannot overwrite selected group`, async () => {
    const f = fixture(mode);
    const old = f.context.loadAccounts();
    f.select.value = '__ungrouped__';
    const current = f.context.loadAccounts();
    assert.equal(f.calls[0].options.signal.aborted, true);
    f.calls[1].resolve({items: [{id: 2}], total: 1});
    await current;
    f.calls[0].resolve({items: [{id: 1}], total: 100});
    await old;
    assert.equal(f.context.ACCOUNTS[0].id, 2);
    assert.equal(f.context.ACCOUNTS_TOTAL, 1);
  });

  test(`${mode}: changing group prevents old polling results from causing reloads`, async () => {
    const f = fixture(mode);
    const oldPoll = f.context.pollAccountPlanStatuses();
    f.select.value = '备用';
    const current = f.context.loadAccounts();
    f.calls[1].resolve({items: [{id: 2}], total: 1});
    await current;
    f.calls[0].resolve({items: [{id: 1}], total: 20, revision: 'old'});
    await oldPoll;
    assert.equal(f.calls.length, 2);
    assert.equal(f.context.ACCOUNTS[0].id, 2);
  });

  test(`${mode}: narrowed group corrects a now-invalid page`, async () => {
    const f = fixture(mode);
    f.context.PAGERS.accounts.page = 4;
    f.select.value = '已卖';
    const list = f.context.loadAccounts();
    f.calls[0].resolve({items: [], total: 1});
    await new Promise(resolve => setImmediate(resolve));
    const url = new URL(f.calls[1].url, 'http://localhost');
    assert.equal(url.searchParams.get('group'), '已卖');
    assert.equal(url.searchParams.get('page'), '1');
    f.calls[1].resolve({items: [{id: 2}], total: 1});
    await list;
    assert.equal(f.context.ACCOUNTS[0].id, 2);
  });
}
