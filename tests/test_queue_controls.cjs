const assert = require('node:assert/strict');
const fs = require('node:fs');
const path = require('node:path');
const vm = require('node:vm');
const {test} = require('node:test');
const templates = path.join(__dirname, '../webui/templates');

for (const mode of ['modern', 'legacy']) {
  function startFixture(count, succeeds = true) {
    const html = fs.readFileSync(path.join(templates, mode === 'modern' ? 'index.html' : 'index_legacy.html'), 'utf8');
    const suffix = mode === 'modern' ? 'V2' : '';
    const nodes = {};
    for (const id of ['regCount','regWorkers','regEmailSource','btnStart','regWarn']) nodes[id+suffix] = {value:'', disabled:false};
    nodes['regCount'+suffix].value = count;
    nodes['regWorkers'+suffix].value = '3';
    let click;
    nodes['btnStart'+suffix].addEventListener = (_event, handler) => click = handler;
    const calls = [], messages = [];
    const context = vm.createContext({
      $: selector => nodes[selector.slice(1)], JOB_STATUS_COUNTS:{active:0}, esc:String,
      api:async (_url, options) => {calls.push(JSON.parse(options.body)); if (!succeeds) throw Error('fixture'); return {submitted:2,workers:3};},
      refreshJobs:()=>{}, setTimeout:callback=>callback(), showToast:message=>messages.push(message),
    });
    const begin = mode === 'modern' ? html.indexOf('async function startRegistrationFromInputs(') : html.indexOf("$('#btnStart').addEventListener('click'");
    vm.runInContext(html.slice(begin, html.indexOf('function selectedPoolItems(', begin)), context);
    const run = mode === 'modern' ? () => context.startRegistrationFromInputs(nodes.regCountV2,nodes.regWorkersV2,nodes.btnStartV2) : () => click();
    return {nodes, calls, messages, run, suffix, html};
  }

  test(`${mode}: blank/fractional registration counts never create a task`, async () => {
    for (const count of ['', '0', '1.5', '201']) {
      const f = startFixture(count); await f.run();
      assert.equal(f.calls.length, 0); assert.equal(f.messages.length, 1);
    }
  });
  test(`${mode}: successful submission clears count; failure retains it`, async () => {
    for (const success of [true, false]) {
      const f = startFixture('2', success); await f.run();
      assert.equal(f.calls.length, 1);
      assert.equal(f.nodes['regCount'+f.suffix].value, success ? '' : '2');
    }
  });
  test(`${mode}: count is next to start and has an empty default`, () => {
    const f = startFixture('2');
    assert.match(f.html, new RegExp(`id="regCount${f.suffix}"[^>]*value=""[^>]*placeholder="-"`));
    const group = f.html.slice(f.html.indexOf('<span class="registration-start-controls">'));
    assert.ok(group.indexOf('regCount'+f.suffix) < group.indexOf('btnStart'+f.suffix));
  });
}

function concurrencyFixture(mode='modern', customApi) {
  const suffix=mode==='modern'?'V2':'';
  const source=fs.readFileSync(path.join(templates,'queue_concurrency_controls.html'),'utf8');
  const nodes={},calls=[],messages=[];
  for(const id of ['regWorkers','codexBulkWorkers','saveRegistrationConcurrency','saveAccountConcurrency','concurrencyHint','accountConcurrencyHint'])
    nodes[id+suffix]={value:'',handlers:{},disabled:false,addEventListener(event,handler){this.handlers[event]=handler;}};
  const state={registration:3,accounts:1};
  const context=vm.createContext({document:{getElementById:id=>nodes[id]},showToast:message=>messages.push(message),
    api:async(url,options)=>{
      calls.push({url,options});
      if(customApi)return customApi(url,options);
      const name=url.includes('/accounts/')?'accounts':'registration';
      if(options)state[name]=JSON.parse(options.body).workers;
      return {workers:state[name]};
    }});
  vm.runInContext(source,context);
  return {nodes,calls,messages,context,suffix};
}
const flushed=()=>new Promise(resolve=>setImmediate(resolve));
for(const mode of ['modern','legacy']) {
  test(`${mode}: page saves are independent and unsaved fields never become the active limit`,async()=>{
    const f=concurrencyFixture(mode);await flushed();
    const n=id=>f.nodes[id+f.suffix];
    assert.equal(n('regWorkers').value,3);assert.equal(n('codexBulkWorkers').value,1);
    n('regWorkers').value='7';n('regWorkers').handlers.input();
    n('codexBulkWorkers').value='4';n('codexBulkWorkers').handlers.input();
    assert.equal(f.context.getSavedAccountWorkers(),1);
    await n('saveAccountConcurrency').handlers.click();
    const accountSave=f.calls.filter(call=>call.options).at(-1);
    assert.equal(accountSave.url,'/api/accounts/concurrency');
    assert.deepEqual(JSON.parse(accountSave.options.body),{workers:4});
    assert.equal(f.context.getSavedAccountWorkers(),4);
    assert.equal(f.context.getSavedRegistrationWorkers(),3);
    assert.equal(n('regWorkers').value,'7');
    assert.match(n('concurrencyHint').textContent,/未保存/);
    await n('saveRegistrationConcurrency').handlers.click();
    const registrationSave=f.calls.filter(call=>call.options).at(-1);
    assert.equal(registrationSave.url,'/api/jobs/concurrency');
    assert.deepEqual(JSON.parse(registrationSave.options.body),{workers:7});
    assert.equal(f.context.getSavedRegistrationWorkers(),7);
    assert.equal(f.context.getSavedAccountWorkers(),4);
    assert.match(n('accountConcurrencyHint').textContent,/本页全部后台任务共用/);
  });
  test(`${mode}: old initial responses cannot overwrite a just-saved page setting`,async()=>{
    const resolves={};
    const f=concurrencyFixture(mode,(url,options)=>options?Promise.resolve({workers:4}):new Promise(resolve=>resolves[url]=resolve));
    const n=id=>f.nodes[id+f.suffix];
    for(const [field,button] of [['regWorkers','saveRegistrationConcurrency'],['codexBulkWorkers','saveAccountConcurrency']]){
      n(field).value='4';n(field).handlers.input();await n(button).handlers.click();
    }
    for(const resolve of Object.values(resolves))resolve({workers:2});
    await flushed();
    assert.equal(Number(n('regWorkers').value),4);assert.equal(Number(n('codexBulkWorkers').value),4);
    assert.equal(f.context.getSavedAccountWorkers(),4);assert.equal(f.context.getSavedRegistrationWorkers(),4);
  });
}
test('bad saves and failed responses never update the active page limit',async()=>{
  const f=concurrencyFixture();await flushed();
  const field=f.nodes.codexBulkWorkersV2,button=f.nodes.saveAccountConcurrencyV2;
  for(const value of ['0','17','2.5','bad']){
    field.value=value;await button.handlers.click();
  }
  assert.equal(f.calls.filter(call=>call.options).length,0);
  assert.equal(f.context.getSavedAccountWorkers(),1);
  const failed=concurrencyFixture('modern',async(_url,options)=>{if(options)throw Error('fixture');return {workers:2};});
  await flushed();failed.nodes.codexBulkWorkersV2.value='4';
  await failed.nodes.saveAccountConcurrencyV2.handlers.click();
  assert.equal(failed.context.getSavedAccountWorkers(),2);
  assert.equal(failed.nodes.saveAccountConcurrencyV2.disabled,false);
  assert.match(failed.messages.at(-1),/保存并发失败/);
});
