const assert=require('node:assert/strict');
const fs=require('node:fs');
const path=require('node:path');
const vm=require('node:vm');
const {test}=require('node:test');
const shared=fs.readFileSync(path.join(__dirname,'../webui/templates/workspace_layout_script.html'),'utf8');
const model=shared.slice(shared.indexOf('const WORKSPACE_PROGRESS_STAGES='),shared.indexOf('let workspaceProgressId='));
function context(extra={}){const c=vm.createContext(extra);vm.runInContext(model,c);return c;}

test('post-registration running 2FA does not make the whole task completed',()=>{
  const c=context();
  const m=c.workspaceProgressModel('[Job 1] 开始注册任务\n[Session] 成功\n[2FA] 阶段1：发起重认证\n[ICAPI] 页面已就绪',
    {status:'running'},{registration:'success',twofa:'running',codex:'skipped'});
  assert.equal(m.finished,false);assert.equal(m.groups[0].state,'success');assert.equal(m.groups[1].state,'running');
  assert.equal(m.groups[1].steps[3].status,'running');assert.equal(m.groups[2].state,'skipped');
  assert.ok(m.groups[2].steps.every(s=>s.status==='skipped'));assert.match(m.current,/2FA/);
});
test('failure after account creation keeps registration done and 2FA stopped',()=>{
  const c=context();const m=c.workspaceProgressModel('[2FA] 正在提交邮箱重认证 OTP',
    {status:'partial_success',account_id:1},{registration:'success',twofa:'failed',codex:'skipped'});
  assert.equal(m.groups[0].state,'success');assert.equal(m.groups[1].state,'failed');
  assert.equal(m.groups[1].steps[4].status,'failed');assert.equal(m.success,false);
});
test('Codex SMS and API polling have a separate group and no raw response content',()=>{
  const c=context();const m=c.workspaceProgressModel('[Codex] 开始 OAuth\n[Codex] 手机短信发送\n[SMSBower] 轮询取码',
    {status:'running'},{registration:'success',twofa:'skipped',codex:'running'});
  assert.equal(m.groups[2].state,'running');assert.equal(m.groups[2].steps[2].status,'running');
  const done=c.workspaceProgressModel('[Codex] 开始 OAuth\n[Codex] 成功：fixture',{status:'success'},{codex:'success',twofa:'skipped'});
  assert.equal(done.groups[2].steps[2].status,'skipped');
});
test('retry progress ignores earlier success and never claims unsent OTP',()=>{
  const c=context();const m=c.workspaceProgressModel('[Job 1] 开始注册任务\n[2FA] TOTP 激活完成\n[Job 1] 开始注册任务\n[步骤4] authorize URL', {status:'failed'});
  assert.notEqual(m.groups[0].state,'success');assert.equal(m.groups[1].state,'not_started');
  assert.equal(m.groups[0].steps[3].status,'pending');
});
test('historical failure evidence is not replaced by a later account setup',()=>{
  const c=context();const m=c.workspaceProgressModel('[2FA] 正在提交邮箱重认证 OTP\n[2FA] 失败：fixture\n[收尾] 完成：plan=success twofa=failed',
    {status:'partial_success',account_id:1},{registration:'success',twofa:'success',codex:'skipped'});
  assert.equal(m.groups[1].state,'failed');
});
test('raw phase filtering attributes generic OTP lines to their active phase',()=>{
  const c=context();const rows=c.workspaceLogRecords('[OTP] 注册接码\n[2FA] 阶段1\n[ICAPI] 读取\n[Codex] 开始 OAuth\n[SMS] 读取');
  assert.deepEqual(Array.from(rows,r=>r.phase),['registration','twofa','twofa','codex','codex']);
});
test('signature API waiting is visible as mailbox polling, not an unstarted stage',()=>{
  const c=context();const m=c.workspaceProgressModel('[OTP] 页面首次发码请求已确认\n[SMSBower签名API] 等待后读取验证码', {status:'running'});
  assert.equal(m.groups[0].steps[4].status,'running');
});
test('password setup follows 2FA in the second group and stays running until acknowledged',()=>{
  const c=context();const log='[Job 1] 开始注册任务\n[2FA] 完成：fixture\n[密码] 开始：2FA 已完成\n[ICAPI] 页面已就绪';
  const model=c.workspaceProgressModel(log,{status:'running'},{twofa:'success',password:'running',codex:'skipped'});
  assert.equal(model.groups.length,3);assert.equal(model.groups[1].state,'running');
  assert.equal(model.groups[1].steps.at(-1).status,'running');assert.match(model.groups[1].steps.at(-1).label,/GPT 密码/);
  assert.equal(c.workspaceLogRecords(log).at(-1).phase,'password');
  const done=c.workspaceProgressModel(log+'\n[密码] 设置完成：官网已确认',{status:'success'},{twofa:'success',password:'success'});
  assert.equal(done.groups[1].steps.at(-1).status,'success');
  const existing=c.workspaceProgressModel(log+'\n[密码] 已保存 GPT 密码，跳过；不改动已有密码',{status:'success'},{twofa:'success',password:'skipped'});
  assert.equal(existing.groups[1].steps.at(-1).status,'skipped');
  const failed=c.workspaceProgressModel(log+'\n[密码] 未完成（TimeoutError）',{status:'partial_success'},{twofa:'success',password:'failed'});
  assert.equal(failed.groups[1].state,'failed');assert.equal(failed.groups[1].steps.at(-1).status,'failed');
});
test('history filter state survives polling and paged requests include the same filters',async()=>{
  const nodes=new Map(),requests=[];
  const c=context({URLSearchParams,AbortController,esc:x=>String(x||''),short:x=>String(x||''),formatTraffic:()=>'-',
    document:{getElementById:id=>{if(!nodes.has(id))nodes.set(id,{});return nodes.get(id);}},
    api:async url=>{requests.push(url);return {items:[],total:0,status_counts:{}};}});
  const start=shared.indexOf('let workspaceLogPage=');const end=shared.indexOf('mountWorkspaceLayout();',start);
  vm.runInContext(shared.slice(start,end),c);
  vm.runInContext("workspaceLogFilters={q:'fixture@icloud.com',status:'failed',date_from:'2026-10-30'}",c);
  await c.refreshLogHistory();await c.refreshLogHistory();
  for(const url of requests){const q=new URL(url,'http://localhost').searchParams;assert.equal(q.get('q'),'fixture@icloud.com');assert.equal(q.get('status'),'failed');assert.equal(q.get('date_from'),'2026-10-30');}
});
