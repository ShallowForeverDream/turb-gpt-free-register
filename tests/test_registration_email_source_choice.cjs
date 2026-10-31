const assert = require('node:assert/strict');
const fs = require('node:fs');
const path = require('node:path');
const vm = require('node:vm');
const {test} = require('node:test');
const templates = path.join(__dirname, '../webui/templates');

test('modern start button sends the selected mailbox type with count and workers', async () => {
  const source = fs.readFileSync(path.join(templates, 'index.html'), 'utf8');
  const fn = source.slice(source.indexOf('async function startRegistrationFromInputs('), source.indexOf('function selectedPoolItems('));
  const nodes = {regEmailSourceV2:{value:'imap'}, btnStartV2:{disabled:false}, regWarnV2:{}, regCountV2:{}, regWorkersV2:{}};
  const calls = [];
  const context = vm.createContext({
    $: selector => nodes[selector.slice(1)], JOB_STATUS_COUNTS:{active:0}, esc:String,
    api:async (_url, options) => {calls.push(JSON.parse(options.body));return {submitted:2,workers:3};},
    refreshJobs:()=>{}, setTimeout:callback=>callback(),
  });
  vm.runInContext(fn, context);
  await context.startRegistrationFromInputs({value:'2'},{value:'3'},nodes.btnStartV2);
  assert.deepEqual(calls, [{count:2,workers:3,email_source:'imap'}]);
});

test('both UIs provide source options without changing the global configuration', () => {
  const options = fs.readFileSync(path.join(templates,'registration_email_source_options.html'),'utf8');
  for (const value of ['', 'outlook', 'imap', 'generic_api', 'cloudflare_domain']) assert.ok(options.includes(`value="${value}"`));
  for (const file of ['index.html','index_legacy.html']) {
    const source=fs.readFileSync(path.join(templates,file),'utf8');
    assert.match(source,/include 'registration_email_source_options.html'/);
    assert.match(source,/email_source:emailSource/);
  }
});
