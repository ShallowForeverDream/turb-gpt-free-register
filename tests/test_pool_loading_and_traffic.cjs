const assert = require('node:assert/strict');
const fs = require('node:fs');
const path = require('node:path');
const vm = require('node:vm');
const {test} = require('node:test');
const templates = path.join(__dirname, '../webui/templates');

function loaderFixture() {
  const html = fs.readFileSync(path.join(templates,'index.html'),'utf8');
  const source = html.slice(html.indexOf('let poolLoadGeneration ='), html.indexOf('function closeOutlookV2MoreMenus()'));
  let query='alpha', status='';
  const calls=[];
  const context=vm.createContext({AbortController, PAGERS:{outlook:{page:1,size:20}},
    OUTLOOK:[], OUTLOOK_TOTAL:0, getPoolSource:()=> 'icloud', getOutlookQuery:()=>query, getPoolStatus:()=>status,
    api:(url,options)=>new Promise(resolve=>calls.push({url,options,resolve})), renderOutlook:()=>{},
    showToast:message=>{throw Error(message);}});
  vm.runInContext(source,context);
  return {context,calls,setFilters:(q,s)=>{query=q;status=s;}};
}

test('late search responses cannot overwrite the newer unregistered filter', async () => {
  const f=loaderFixture();
  const old=f.context.loadOutlook();
  f.setFilters('beta','unregistered');
  const latest=f.context.loadOutlook();
  assert.equal(f.calls[0].options.signal.aborted,true);
  const url=new URL(f.calls[1].url,'http://localhost');
  assert.equal(url.searchParams.get('q'),'beta');
  assert.equal(url.searchParams.get('status'),'unregistered');
  assert.equal(url.searchParams.get('source'),'icloud');
  f.calls[1].resolve({items:[{email:'beta@icloud.com'}],total:1});await latest;
  f.calls[0].resolve({items:[{email:'old@icloud.com'}],total:100});await old;
  assert.equal(f.context.OUTLOOK[0].email,'beta@icloud.com');
  assert.equal(f.context.OUTLOOK_TOTAL,1);
});

test('a filter that reduces the page count requests page one correctly', async () => {
  const f=loaderFixture();
  f.context.PAGERS.outlook.page=3;
  const load=f.context.loadOutlook();
  f.calls[0].resolve({items:[],total:1});
  await new Promise(resolve=>setImmediate(resolve));
  assert.equal(f.context.PAGERS.outlook.page,1);
  assert.equal(new URL(f.calls[1].url,'http://localhost').searchParams.get('page'),'1');
  f.calls[1].resolve({items:[{email:'only@icloud.com'}],total:1});await load;
  assert.equal(f.context.OUTLOOK[0].email,'only@icloud.com');
});

test('traffic is total/dynamic IP in MiB without budget or verbose rows', () => {
  const context=vm.createContext({esc:String});
  vm.runInContext(fs.readFileSync(path.join(templates,'traffic_display.html'),'utf8'),context);
  const html=context.formatTraffic({available:true,total_bytes:1.47*1048576,dynamic_ip_bytes:1.23*1048576,
    traffic_schema_version:2,within_budget:false});
  assert.match(html,/>1\.47MiB\/1\.23MiB</);
  assert.doesNotMatch(html,/超预算|↑|↓|<div/);
  assert.match(context.formatTraffic({available:true,total_bytes:1048576}),/>1\.00MiB\/—</);
});

test('iCloud has both a sidebar shortcut and a source filter', () => {
  const source=fs.readFileSync(path.join(templates,'index.html'),'utf8');
  assert.match(source,/data-tab="icloud"/);
  assert.match(source,/data-value="icloud"/);
});
