const assert=require('node:assert/strict');
const fs=require('node:fs');
const path=require('node:path');
const vm=require('node:vm');
const {test}=require('node:test');
const templates=path.join(__dirname,'../webui/templates');
const read=name=>fs.readFileSync(path.join(templates,name),'utf8');
const shared=read('workspace_layout_script.html');
for(const name of ['index.html','index_legacy.html']){
  test(`${name}: exactly five navigation pages and shared layout`,()=>{
    const html=read(name),nav=html.slice(html.indexOf('<nav'),html.indexOf('</nav>'));
    assert.deepEqual([...nav.matchAll(/data-tab="([^"]+)"/g)].map(m=>m[1]),['register','accounts','github','outlook','config']);
    for(const title of ['日志','GPT账号','github账号','邮箱池','配置'])assert.ok(nav.includes(title));
    for(const include of ['workspace_styles.html','workspace_pages.html','workspace_layout_script.html','account_workspace_layout.html'])assert.ok(html.includes(`include '${include}'`));
    assert.ok(!html.includes("include 'live_check_guidance.html'"));
    assert.ok(html.includes("if (tab === 'codex') tab = 'accounts'"));
    assert.ok(html.includes("pollVisiblePage('register', refreshLogHistory"));
    assert.ok(html.includes("pollVisiblePage('outlook', refreshJobs"));
    assert.ok(html.includes('return openAccountExportDialog();'));
  });
}
test('toolbar has three rows, ordered groups and explicit SMS information only',()=>{
  const html=read('account_workspace_layout.html');
  assert.equal([...html.matchAll(/class="workspace-row"/g)].length,3);
  assert.deepEqual([...html.matchAll(/data-workspace-slot="([^"]+)"/g)].map(m=>m[1]),['basic','codex','business','account','concurrency','refresh','export','import']);
  assert.ok(html.includes('不会购号、扣费'));
  assert.ok(shared.includes("document.getElementById('codexSmsInfo').showModal()"));
  assert.ok(!shared.includes('/api/manual-otp'));
});
test('archive toggle preserves other column filters and resets only account page',()=>{
  const nodes=new Map([['workspaceArchiveToggle',{textContent:''}],['workspaceAccountSelection',{}]]);
  let loads=0,events=0;
  const context=vm.createContext({ACCOUNT_COLUMN_FILTER_STATE:{status:{values:['unarchived']},email:{text:'example.test'}},
    ACCOUNT_SELECTED:new Set([1]),PAGERS:{accounts:{page:3},jobs:{page:2}},SHOW_ARCHIVED_ACCOUNTS:false,
    document:{getElementById:id=>nodes.get(id),dispatchEvent:()=>events++},Event:class{},loadAccounts:()=>loads++});
  const start=shared.indexOf('function syncWorkspaceAccountControls()');
  const end=shared.indexOf('async function setWorkspaceAccountGroup');
  vm.runInContext(shared.slice(start,end),context);
  context.toggleWorkspaceArchive();
  assert.deepEqual(context.ACCOUNT_COLUMN_FILTER_STATE.email,{text:'example.test'});
  assert.equal(context.ACCOUNT_COLUMN_FILTER_STATE.status.values[0],'archived');
  assert.equal(nodes.get('workspaceArchiveToggle').textContent,'未归档');
  assert.equal(context.PAGERS.accounts.page,1);assert.equal(context.PAGERS.jobs.page,2);
  assert.equal(context.ACCOUNT_SELECTED.size,0);assert.equal(loads,1);assert.equal(events,1);
  context.toggleWorkspaceArchive();assert.equal(context.ACCOUNT_COLUMN_FILTER_STATE.status.values[0],'unarchived');
});
test('registration controls are moved without cloning listeners and log history is read-only',()=>{
  assert.ok(shared.includes('pool.prepend(registration);pool.append(tasks)'));
  assert.ok(shared.includes("tasks.append(document.getElementById('jobsPanelV2'))"));
  const history=shared.slice(shared.indexOf('async function refreshLogHistory()'));
  assert.ok(history.includes('new URLSearchParams'));
  assert.ok(history.includes("paged:'1'"));
  assert.ok(!history.includes("method:'POST'"));
  assert.ok(history.includes('workspaceLogAbort?.abort()'));
  assert.ok(history.includes('request!==workspaceLogRequest'));
  assert.ok(history.includes('esc(job.email)'));
});
test('account dialogs send selected fields and never persist pasted secrets',()=>{
  const code=read('registered_import_script.html');
  assert.ok(code.includes('JSON.stringify({text,fields})'));
  assert.ok(code.includes("body.append('fields',JSON.stringify(fields))"));
  assert.ok(code.includes('JSON.stringify({ids,fields})'));
  assert.ok(!code.includes('localStorage'));
  assert.ok(code.includes("addEventListener('close'"));
  assert.ok(code.includes('accountExportIds=ids'));
});
test('visual progress treats third-party login as verification boundary, not mailbox OTP',()=>{
  const source=shared.slice(shared.indexOf('const WORKSPACE_PROGRESS_STAGES='),shared.indexOf('let workspaceProgressId='));
  const context=vm.createContext({});vm.runInContext(source,context);
  const result=context.workspaceProgressModel('[步骤4] 重定向完成, 最终URL: https://accounts.google.com/v3/signin/identifier',
    {status:'failed',status_message:'未进入邮箱验证页；请人工确认'});
  assert.equal(result.index,3);assert.equal(result.thirdParty,true);assert.equal(result.finished,true);
  assert.equal(result.success,false);
  const redacted=context.workspaceProgressModel('',{status:'failed',error_message:'URL https://x.example/path?key=secret code 123456'});
  assert.ok(!redacted.note.includes('key=secret'));assert.ok(!redacted.note.includes('123456'));
});
test('history remains read-only and uses a colored progress view with explicit raw log',()=>{
  const html=read('workspace_pages.html'),css=read('workspace_styles.html');
  assert.ok(html.includes('workspaceProgressDialog'));
  assert.ok(html.includes('查看原始日志'));
  assert.ok(shared.includes('openWorkspaceProgress(Number(button.dataset.historyLog))'));
  assert.ok(shared.includes('workspaceLogSignature'));
  assert.ok(css.includes('tr[data-state=success]'));
  assert.ok(css.includes('.accounts-table-v2 th:nth-child(2)'));
  assert.ok(css.includes('.workspace-registration .queue-concurrency-hint{display:none'));
});
