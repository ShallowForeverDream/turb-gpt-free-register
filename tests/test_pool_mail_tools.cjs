const assert = require('node:assert/strict');
const fs = require('node:fs');
const path = require('node:path');
const vm = require('node:vm');
const {test} = require('node:test');
const templates = path.join(__dirname, '../webui/templates');
const tools = fs.readFileSync(path.join(templates, 'pool_mail_tools.html'), 'utf8');

function fixture(api = async () => ({code: '001234'})) {
  const copied = new Map();
  const messages = [];
  const context = vm.createContext({
    esc: s => String(s).replaceAll('&', '&amp;').replaceAll('<', '&lt;').replaceAll('>', '&gt;').replaceAll('"', '&quot;'),
    copyId: value => { const id = `copy${copied.size}`; copied.set(id, value); return id; },
    renderOutlook: () => {}, showToast: s => messages.push(s), api,
  });
  vm.runInContext(tools, context);
  return {context, copied, messages, cache: vm.runInContext('POOL_EMAIL_OTP_CACHE', context)};
}

test('clicking the email address copies only the email, never its material line', () => {
  const {context, copied} = fixture();
  const email = 'fixture+alias@example.test';
  const html = context.poolEmailAddressCell({email, password: 'mail-password',
    refresh_token: 'refresh-token', copy_line: email+'----mail-password----client----refresh-token'});
  assert.equal(copied.get('copy0'), email);
  assert.match(html, /pool-email-address/);
  assert.match(html, /点击仅复制邮箱地址/);
  assert.doesNotMatch(html, /mail-password|refresh-token|----/);
});

test('forwarded rows display their own receiver without copying it with the alias',()=>{
  const {context,copied}=fixture();
  const html=context.poolEmailAddressCell({email:'alias@icloud.com',imap_forwarded:true,imap_username:'receiver@163.com'});
  assert.match(html,/接码：receiver@163.com/);
  assert.deepEqual([...copied.values()],['alias@icloud.com']);
});

test('mailbox passwords are plain escaped text and copy the original value', () => {
  const {context, copied} = fixture();
  const password = 'mail<&" password';
  const html = context.poolEmailPasswordCell({source: 'outlook', password});
  assert.match(html, /account-password-text/);
  assert.match(html, /mail&lt;&amp;&quot; password/);
  assert.equal(copied.get('copy0'), password);
  assert.match(context.poolEmailPasswordCell({source: 'imap', imap_password: 'imap-password'}), /imap-password/);
});

test('forwarded mailboxes never display or copy the receiver authorization', () => {
  const {context, copied} = fixture();
  const html = context.poolEmailPasswordCell({source: 'imap', imap_forwarded: true,
    password: 'receiver-authorization', imap_password: 'receiver-authorization'});
  assert.doesNotMatch(html, /receiver-authorization|data-copy-id/);
  assert.equal(copied.size, 0);
  assert.doesNotMatch(context.poolEmailPasswordCell({source: 'outlook'}), /data-copy-id/);
});

test('queries encode the exact email and source and preserve leading zeros', async () => {
  const calls = [];
  const {context, copied} = fixture(async url => { calls.push(url); return {code: '001234'}; });
  const email = 'fixture+alias@example.test';
  await context.queryPoolEmailOtp(email, 'imap');
  assert.equal(calls[0], '/api/outlook/email-otp?email=fixture%2Balias%40example.test&source=imap');
  const html = context.poolEmailOtpCell({email, source: 'imap'});
  assert.match(html, /001234/);
  assert.match(html, /刷新/);
  assert.match(html, /复制验证码/);
  assert.equal(copied.get('copy0'), '001234');
});

test('a repeated click does not start two reads of the same mailbox', async () => {
  let finish, count = 0;
  const {context} = fixture(() => { count++; return new Promise(resolve => { finish = resolve; }); });
  const pending = context.queryPoolEmailOtp('fixture@example.test', 'outlook');
  const html = context.poolEmailOtpCell({email: 'fixture@example.test', source: 'outlook'});
  assert.match(html, /aria-label="正在查询邮箱验证码"/);
  assert.match(html, /aria-busy="true"/);
  assert.match(html, / disabled/);
  await context.queryPoolEmailOtp('fixture@example.test', 'outlook');
  assert.equal(count, 1);
  finish({code: '001234'});
  await pending;
});

test('a failed refresh clears the old code and allows another query', async () => {
  const {context, cache, messages} = fixture(async () => { throw new Error('fixture failure'); });
  cache.set('imap|fixture@example.test', {code: '999999', fetchedAt: Date.now(), at: 'fixture time'});
  await context.queryPoolEmailOtp('fixture@example.test', 'imap');
  const html = context.poolEmailOtpCell({email: 'fixture@example.test', source: 'imap'});
  assert.doesNotMatch(html, /999999|disabled/);
  assert.match(html, /aria-label="查询邮箱验证码"/);
  assert.match(messages[0], /fixture failure/);
});

test('cache entries expire and stay separate for identical emails in different sources', () => {
  const {context, cache} = fixture();
  cache.set('imap|fixture@example.test', {code: '999999', fetchedAt: Date.now() - 900001, at: ''});
  assert.doesNotMatch(context.poolEmailOtpCell({email: 'fixture@example.test', source: 'imap'}), /999999/);
  cache.set('imap|fixture@example.test', {code: '999999', fetchedAt: Date.now(), at: ''});
  assert.doesNotMatch(context.poolEmailOtpCell({email: 'fixture@example.test', source: 'outlook'}), /999999/);
});

test('both UI modes have ten aligned pool columns and use shared mail controls', () => {
  for (const [file, cls] of [['index.html', 'outlook-table-v2'], ['index_legacy.html', 'outlook-table']]) {
    const source = fs.readFileSync(path.join(templates, file), 'utf8');
    const table = source.match(new RegExp(`<table class="${cls}">([\\s\\S]*?)</table>`))[1];
    assert.equal((table.match(/<col\s/g) || []).length, 10);
    assert.equal((table.match(/<th(?:\s|>)/g) || []).length, 10);
    assert.match(table, /邮箱密码/);
    assert.match(table, /邮箱验证码/);
    assert.match(source, /include 'pool_mail_tools.html'/);
    assert.match(source, /poolEmailPasswordCell\(r\)/);
    assert.match(source, /poolEmailAddressCell\(r\)/);
    assert.match(source, /cbtn\('复制邮箱', r.email/);
    assert.doesNotMatch(source, /cbtn\('复制邮箱', r.copy_line/);
    assert.match(source, /poolEmailOtpCell\(r\)/);
    assert.match(source, /queryPoolEmailOtp\(otpButton.dataset.email, otpButton.dataset.source\)/);
    assert.match(source, /outlook-mail-tools-v1/);
  }
});

test('OTP actions use compact accessible icons instead of the old text buttons', () => {
  const {context} = fixture();
  const html = context.poolEmailOtpCell({email: 'fixture@example.test', source: 'outlook'});
  assert.match(html, /class="pool-otp-button"/);
  assert.match(html, /<svg[^>]*aria-hidden="true"/);
  assert.match(html, /aria-label="查询邮箱验证码"/);
  assert.doesNotMatch(html, /acc-v2-twofa-btn|>查验证码</);
});
