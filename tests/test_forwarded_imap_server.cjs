const assert = require('node:assert/strict');
const fs = require('node:fs');
const path = require('node:path');
const vm = require('node:vm');
const {test} = require('node:test');

const source = fs.readFileSync(path.join(__dirname, '../webui/templates/forwarded_imap_server.html'), 'utf8');

function suggest(inboxValue, serverValue) {
  const inbox = {value: inboxValue};
  const server = {value: serverValue};
  const context = vm.createContext({document: {getElementById(id) { return id === 'inbox' ? inbox : server; }}});
  vm.runInContext(source, context);
  context.suggestForwardedImapServer('inbox', 'server');
  return server.value;
}

test('yeah.net mailbox selects its IMAP server', () => {
  assert.equal(suggest('18900281792@yeah.net', 'imap.163.com'), 'imap.yeah.net');
});

test('custom server remains untouched and 163.com uses its own server', () => {
  assert.equal(suggest('user@yeah.net', 'imap.example.test'), 'imap.example.test');
  assert.equal(suggest('user@163.com', ''), 'imap.163.com');
});
