const assert=require('node:assert/strict');
const fs=require('node:fs');
const path=require('node:path');
const vm=require('node:vm');
const {test}=require('node:test');
const templates=path.join(__dirname,'../webui/templates');
function fixture(){
  const context=vm.createContext({document:{querySelectorAll:()=>[]}});
  vm.runInContext(fs.readFileSync(path.join(templates,'account_column_filters.html'),'utf8'),context);
  return context;
}
test('column state starts with unarchived only and serializes arrays without flattening',()=>{
  const context=fixture();
  assert.deepEqual(JSON.parse(context.getAccountColumnFiltersQuery()),{status:{values:['unarchived']}});
  vm.runInContext("ACCOUNT_COLUMN_FILTER_STATE.plan={values:['plus_half_1m','go_trial_1m']}",context);
  assert.deepEqual(JSON.parse(context.getAccountColumnFiltersQuery()).plan.values,['plus_half_1m','go_trial_1m']);
});
test('multi selection stays separate from candidate-search text and preserves date ranges',()=>{
  const context=fixture();
  const result=context.accountColumnFilterValue({values:new Set(['a@example.test','b@example.test'])},{from:{value:'2026-10-01'},to:{value:'2026-10-31'}});
  assert.deepEqual(JSON.parse(JSON.stringify(result)),{values:['a@example.test','b@example.test'],from:'2026-10-01',to:'2026-10-31'});
  assert.throws(()=>context.accountColumnFilterValue({values:new Set()},{from:{value:'2026-10-31'},to:{value:'2026-10-01'}}),/开始日期/);
});
test('traffic numeric bounds validate before a request and blank fields clear correctly',()=>{
  const context=fixture();
  const result=context.accountColumnFilterValue({values:new Set()},{min:{value:'1.25'},max:{value:'2.5'},dynamic_min:{value:''}});
  assert.deepEqual(JSON.parse(JSON.stringify(result)),{min:1.25,max:2.5});
  assert.throws(()=>context.accountColumnFilterValue({values:new Set()},{min:{value:'3'},max:{value:'2'}}),/最小流量/);
});
test('shared header contains precisely the sixteen requested filter keys and compact markers',()=>{
  const header=fs.readFileSync(path.join(templates,'account_table_header.html'),'utf8');
  const keys=[...header.matchAll(/\('([^']+)'\s*,/g)].map(match=>match[1]);
  assert.deepEqual(keys,['id','status','email','group','source','email_otp','token','gpt_password','mail_password','plan','note','twofa','codex','registered_at','traffic','actions']);
  assert.match(header,/aria-haspopup="dialog"/);assert.match(header,/aria-hidden="true">·/);
  assert.doesNotMatch(header,/<select|<input/);
});

test('old account widths migrate to the same semantic columns, not to new status/group columns',()=>{
  const values=new Map([['table-widths:accounts',JSON.stringify({1:100,2:450,3:80,8:260,14:150})]]);
  const localStorage={getItem:key=>values.get(key)??null,setItem:(key,value)=>values.set(key,value)};
  const context=vm.createContext({localStorage});
  vm.runInContext(fs.readFileSync(path.join(templates,'account_column_widths.html'),'utf8'),context);
  const key=context.tableColumnWidthStorageKey('table-widths','accounts');
  const widths=JSON.parse(values.get(key));
  assert.equal(widths[3],450);assert.equal(widths[5],80);assert.equal(widths[10],260);assert.equal(widths[16],150);
  assert.equal(widths[2],undefined);assert.equal(widths[4],undefined);
  values.set(key,JSON.stringify({3:500}));context.tableColumnWidthStorageKey('table-widths','accounts');
  assert.deepEqual(JSON.parse(values.get(key)),{3:500});
  assert.equal(context.tableColumnWidthStorageKey('table-widths','jobs'),'table-widths:jobs');
});
