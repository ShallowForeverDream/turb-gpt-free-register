const assert=require('node:assert/strict');
const fs=require('node:fs');const path=require('node:path');const vm=require('node:vm');const {test}=require('node:test');
const base=path.join(__dirname,'../webui/templates');const read=n=>fs.readFileSync(path.join(base,n),'utf8');
for(const name of ['index.html','index_legacy.html'])test(name+' Grok navigation and namespace separation',()=>{
  const s=read(name),nav=s.slice(s.indexOf('<nav'),s.indexOf('</nav>'));
  assert.deepEqual([...nav.matchAll(/data-tab="([^"]+)"/g)].map(m=>m[1]),['outlook','accounts','grok','register','config']);
  assert.ok(s.includes("if (tab === 'grok') loadGrok()"));assert.ok(s.includes("include 'grok_script.html'"));
  assert.ok(s.includes('poolPlatformStatus(r)'));assert.ok(!nav.includes('github'));
});
test('Grok view only lists registered accounts and no mailbox/job panels',()=>{
  const html=read('grok_page.html'),script=read('grok_script.html');
  for(const id of ['tab-grok','grokAccountRows','grokCodeForm','grokLogDialog','pager-grok-accounts'])assert.ok(html.includes(id));
  for(const removed of ['grokMailboxRows','grokJobRows','grokPrev','grokNext','grokSource'])assert.ok(!html.includes(removed));
  assert.ok(html.includes('accounts-panel-v2'));assert.ok(html.includes('accounts-table-v2'));
  assert.ok(script.includes('/api/grok'));assert.ok(!script.includes('localStorage'));assert.ok(!script.includes('/api/accounts/'));
  assert.ok(script.includes('data-grok-secret'));assert.ok(script.includes('grokGeneration'));assert.ok(script.includes('textContent=grokLogText'));
});
test('Grok registration controls live in the mailbox pool page and are separated from GPT',()=>{
  const pages=read('workspace_pages.html'),script=read('grok_script.html'),layout=read('workspace_layout_script.html');
  assert.ok(pages.includes("include 'grok_registration_panel.html'"));
  const panel=read('grok_registration_panel.html');
  for(const id of ['grokRegistrationBlock','grokStart','grokWorkers','grokDriver','grokImportMailViews','grokQueueState'])assert.ok(panel.includes(id));
  assert.ok(script.includes("grokPost('/jobs'"));
  assert.ok(layout.includes("registration-block--gpt"));
  assert.ok(layout.includes("poolTitle.insertAdjacentElement('afterend',registration)"));assert.ok(layout.includes("registration.insertAdjacentElement('afterend',grokBlock)"));
});
test('Grok account rows expose official CLI auth actions',()=>{
  const html=read('grok_page.html'),script=read('grok_script.html');
  assert.ok(html.includes('Grok CLI'));assert.ok(script.includes('下载 auth.json'));
  assert.ok(script.includes('data-grok-cli='));assert.ok(script.includes('cli-auth/download'));
});
test('Pool distinguishes platform states and escapes email-derived state text',()=>{
  const s=read('grok_script.html');const start=s.indexOf('function poolPlatformStatus('),end=s.indexOf('\nfunction grokPost',start);
  const ctx=vm.createContext({esc:s=>String(s).replaceAll('<','&lt;').replaceAll('>','&gt;'),GROK_LABELS:{registered:'已注册',unregistered:'未注册'}});
  vm.runInContext(s.slice(start,end),ctx);
  const html=ctx.poolPlatformStatus({registration_status:'registered',grok_registration_status:'unregistered'});
  assert.match(html,/GPT：已注册/);assert.match(html,/Grok：未注册/);
  assert.ok(!ctx.poolPlatformStatus({grok_registration_status:'<img>'}).includes('<img>'));
});
test('Shared history has platform selector and separate Grok log IDs',()=>{
  assert.ok(read('workspace_pages.html').includes('name="platform"'));assert.ok(read('workspace_layout_script.html').includes('/api/grok/jobs?'));
  assert.ok(read('workspace_layout_script.html').includes('data-grok-log'));
});

test('Grok manual handoff is explicit and does not silently replay signup',()=>{
  const html=read('grok_page.html'),script=read('grok_script.html');
  assert.ok(html.includes('id="grokContinue" hidden'));
  assert.ok(script.includes('confirmed:true'));
  assert.ok(script.includes("r.stage!=='access_check'"));
});

test('Mail viewer links import as mappings and never start registration',()=>{
  const panel=read('grok_registration_panel.html'),script=read('grok_script.html');
  for(const id of ['grokImportMailViews','grokMailViewsFile'])assert.ok(panel.includes(`id="${id}"`));
  assert.ok(script.includes("grokPost('/mailboxes/viewer-links'"));
  assert.ok(script.includes('未启动注册'));
});

test('Capture imports are explicitly labeled as manual and not live-verified',()=>{
  const s=read('grok_script.html'),start=s.indexOf('function grokAccountStatus('),end=s.indexOf('\nfunction grokPost(',start);
  const context=vm.createContext({});vm.runInContext(s.slice(start,end),context);
  assert.match(context.grokAccountStatus({registration_origin:'manual_capture'}),/人工抓包导入.*未在线复验/);
  assert.ok(s.includes('esc(grokAccountStatus(r))'));
});

test('Grok starts with protocol selected and sends the explicit driver',()=>{
  const panel=read('grok_registration_panel.html'),script=read('grok_script.html');
  assert.match(panel, /id="grokDriver">\s*<option value="protocol"/);
  assert.ok(script.includes("document.getElementById('grokDriver').value"));
  assert.ok(script.includes('authorized:true,driver'));
});

test('Native verification window requires a separate explicit confirmation',()=>{
  const html=read('grok_page.html'),script=read('grok_script.html');
  assert.ok(html.includes('id="grokNativeVerify" hidden'));
  assert.ok(script.includes('/verify-native'));
  assert.ok(script.includes("r.stage!=='native_challenge'"));
});

test('Protocol account label does not imply a live model API entitlement',()=>{
  const s=read('grok_script.html'),start=s.indexOf('function grokAccountStatus('),end=s.indexOf('\nfunction grokPost(',start);
  const context=vm.createContext({});vm.runInContext(s.slice(start,end),context);
  assert.match(context.grokAccountStatus({registration_origin:'protocol'}), /协议注册.*未验证API套餐/);
});
