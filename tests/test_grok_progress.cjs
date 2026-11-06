const assert=require('node:assert/strict');
const fs=require('node:fs');const path=require('node:path');const vm=require('node:vm');const {test}=require('node:test');
const base=path.join(__dirname,'../webui/templates');const read=n=>fs.readFileSync(path.join(base,n),'utf8');
test('Grok visual progress works for browser and protocol tasks',()=>{
  const s=read('grok_script.html');const start=s.indexOf('const GROK_PROGRESS_GROUPS');const end=s.indexOf('function openGrokProgress',start);
  const context=vm.createContext({});vm.runInContext(s.slice(start,end)+'\n;globalThis.__model=grokProgressModel;',context);
  const browser={status:'success',events:[
    {message:'动态家宽出口已固定：socks5://***:***@proxy:3000；本任务全程复用'},
    {message:'开始 Grok 注册（driver=browser）；不占用 GPT 邮箱注册状态'},
    {message:'已打开独立的普通浏览器；人机验证请在浏览器中人工完成'},
    {message:'浏览器已提交邮箱发码请求一次；30秒后只读API，不重发'},
    {message:'第 1/3 次 API 读取：取得 Grok 格式验证码'},
    {message:'验证码已填写一次'},
    {message:'浏览器已提交原生建号请求；等待服务端确认'},
    {message:'浏览器登录态已确认本任务邮箱与验证状态；保存 Grok SSO'},
    {message:'Grok 注册已完成；开始官方 Grok CLI 设备授权'},
    {message:'Grok CLI 授权完成'}
  ]};
  const m=context.__model(browser);
  assert.equal(m.success,true);
  assert.equal(m.groups.length,3);
  assert.equal(m.groups[0].steps[0].status,'success');
  assert.equal(m.groups[1].steps[1].status,'success');
  assert.equal(m.groups[2].state,'success');
  const protocol=context.__model({status:'blocked',events:[{message:'原生HTTP预检 grok.com'},{message:'原生SDK安全上下文尚未接通'}]});
  assert.equal(protocol.finished,true);assert.equal(protocol.success,false);
  assert.equal(protocol.groups[1].state,'skipped');
});
