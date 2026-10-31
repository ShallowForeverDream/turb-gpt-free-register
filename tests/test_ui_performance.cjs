const assert=require('node:assert/strict');
const fs=require('node:fs');
const path=require('node:path');
const vm=require('node:vm');
const {test}=require('node:test');
const templates=path.join(__dirname,'../webui/templates');
const helpers=fs.readFileSync(path.join(templates,'ui_performance.html'),'utf8');

test('hundreds of refreshes retain only current copy references for each page',()=>{
  const context=vm.createContext({copyStore:new Map()});vm.runInContext(helpers,context);
  let sequence=0;
  for(let round=0;round<500;round++)for(const scope of ['accounts','outlook','codex']){
    context.withCopyScope(scope,()=>{
      for(let i=0;i<30;i++){const id='c'+(++sequence);context.copyStore.set(id,'fixture');context.rememberCopyId(id);}
    });
  }
  assert.equal(context.copyStore.size,90);
  context.copyStore.set('modal','fixture');context.rememberCopyId('modal');
  assert.throws(()=>context.withCopyScope('accounts',()=>{throw Error('fixture');}),/fixture/);
  context.withCopyScope('outlook',()=>{});
  assert.equal(context.copyStore.get('modal'),'fixture');
  assert.equal(context.copyStore.size,61);
});

test('one visible poll never overlaps requests or runs against a hidden page',async()=>{
  let tick,visible,finish,calls=0,hiddenTab=false;
  const document={hidden:false,getElementById:()=>({classList:{contains:()=>hiddenTab}}),
    addEventListener:(_event,listener)=>visible=listener};
  const context=vm.createContext({copyStore:new Map(),document,setInterval:fn=>{tick=fn;return 1;}});
  vm.runInContext(helpers,context);
  context.pollVisiblePage('accounts',()=>{calls++;return new Promise(resolve=>finish=resolve);},10);
  const pending=tick();await tick();await tick();assert.equal(calls,1);
  finish();await pending;
  document.hidden=true;await tick();assert.equal(calls,1);
  document.hidden=false;hiddenTab=true;await tick();assert.equal(calls,1);
  hiddenTab=false;visible();assert.equal(calls,2);finish();
});

for(const mode of ['modern','legacy']){
  const html=fs.readFileSync(path.join(templates,mode==='modern'?'index.html':'index_legacy.html'),'utf8');
  test(`${mode}: all three tables scope copy references and no action creates a list-poll interval`,()=>{
    for(const name of ['Accounts','Outlook','Codex'])assert.match(html,new RegExp(`function render${name}\\(\\) \\{ return withCopyScope`));
    assert.doesNotMatch(html,/setInterval\(loadAccounts/);
    assert.match(html,/pollVisiblePage\('accounts', pollAccountPlanStatuses/);
  });
  test(`${mode}: late task and Codex responses cannot overwrite the newest page`,async()=>{
    for(const [fn,next,version,page] of [['refreshJobs','async function refreshRegistrationPauseStatus','jobsRequest','jobs'],
                                       ['loadCodex',mode==='modern'?'const CODEX_SELECTED':'function renderCodex','codexRequest','codex']]){
      const start=html.indexOf('let '+version+'Version');
      const stop=html.indexOf('\n}',start)+2;
      const source=html.slice(start,stop);
      const calls=[];let rendered=0;
      const context=vm.createContext({AbortController,PAGERS:{[page]:{page:1,size:20}},
        JOBS:[],JOBS_TOTAL:0,JOB_STATUS_COUNTS:{},jobsRenderSignature:'',CODEX:[],CODEX_TOTAL:0,
        CODEX_SHOW_ARCHIVED:false,getCodexQuery:()=>'',renderJobs:()=>rendered++,renderCodex:()=>rendered++,
        refreshRegistrationPauseStatus:()=>{},loadSummary:()=>{},
        document:{getElementById:()=>({value:''})},$:()=>({value:'',textContent:''}),
        api:(url,options)=>new Promise(resolve=>calls.push({url,options,resolve})),showToast:()=>{}});
      vm.runInContext(source,context);
      const old=context[fn]();context.PAGERS[page].page=2;const latest=context[fn]();
      assert.equal(calls[0].options.signal.aborted,true);
      const payload=id=>page==='jobs'?{items:[{id}],total:100,status_counts:{}}:{accounts:[{id}],total:100,summary:{}};
      calls[1].resolve(payload(2));await latest;calls[0].resolve(payload(1));await old;
      assert.equal((page==='jobs'?context.JOBS:context.CODEX)[0].id,2);
      assert.equal(rendered,1);
    }
  });
  test(`${mode}: configuration drafts survive a slow response and unchanged values do not rebuild the form`,async()=>{
    const start=html.indexOf('let configFlight = null');const stop=html.indexOf('\n}',start)+2;
    const source=html.slice(start,stop);let resolve,calls=0,rendered=0;
    const context=vm.createContext({CONFIG:[],CONFIG_PENDING_UPDATES:{},
      api:()=>{calls++;return new Promise(r=>resolve=r);},renderConfigLayoutV2:()=>rendered++,bindConfigLayoutV2:()=>{},
      renderConfigTabs:()=>{},renderConfigPanel:()=>rendered++,$:()=>({innerHTML:''}),showToast:()=>{}});
    vm.runInContext(source,context);
    const first=context.loadConfig();const duplicate=context.loadConfig();assert.equal(calls,1);
    context.CONFIG_PENDING_UPDATES.fixture='draft';resolve([{key:'fixture',value:'server'}]);await first;await duplicate;
    assert.equal(rendered,0);await context.loadConfig();assert.equal(calls,1);
    delete context.CONFIG_PENDING_UPDATES.fixture;
    const applied=context.loadConfig();resolve([{key:'fixture',value:'server'}]);await applied;assert.equal(rendered,1);
    const same=context.loadConfig();resolve([{key:'fixture',value:'server'}]);await same;assert.equal(rendered,1);
  });
  test(`${mode}: unchanged status responses do not clear the table or trigger a full reload`,async()=>{
    const start=html.indexOf('async function pollAccountPlanStatuses()');const stop=html.indexOf('\n}',start)+2;
    const calls=[];
    const context=vm.createContext({planStatusLoading:false,accountsLoading:false,accountsLoadGeneration:1,
      planStatusRevision:'fixture-revision',SHOW_ARCHIVED_ACCOUNTS:false,PAGERS:{accounts:{page:1,size:20}},
      getAccountsPlanFilter:()=>'',getAccountsCodexFilter:()=>'',getAccountsTotpFilter:()=>'',getAccountsQuery:()=>'',
      getAccountsEmailSuffix:()=>'',getAccountsGroup:()=>'',document:{getElementById:()=>({value:''})},$:()=>({value:''}),
      api:async url=>{calls.push(url);return {unchanged:true,revision:'fixture-revision'};},
      renderAccounts:()=>{throw Error('unnecessary table render');},loadAccounts:()=>{throw Error('unnecessary full reload');}});
    vm.runInContext(html.slice(start,stop),context);await context.pollAccountPlanStatuses();
    assert.equal(calls.length,1);
    assert.equal(new URL(calls[0],'http://localhost').searchParams.get('revision'),'fixture-revision');
    assert.equal(context.planStatusLoading,false);
  });
}
