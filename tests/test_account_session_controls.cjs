const assert=require('node:assert/strict');
const fs=require('node:fs');
const path=require('node:path');
const vm=require('node:vm');
const {test}=require('node:test');
const base=path.join(__dirname,'../webui/templates');
const shared=fs.readFileSync(path.join(base,'account_session_controls.html'),'utf8');
function context(){const c=vm.createContext({esc:x=>String(x??''),EMAIL_OTP_CACHE:new Map()});vm.runInContext(shared,c);return c;}

test('Session copy buttons contain only account ID and requested field, never secret values',()=>{
  const c=context();const html=c.accountSessionCopyControls({id:5,has_session_token:true,has_session_json:true,
    session_token:'private-cookie',session_json:{accessToken:'private-at'}},'fixture-class');
  assert.match(html,/data-account-copy-secret="session_token"/);assert.match(html,/data-account-copy-secret="session_json"/);
  assert.match(html,/复制SESSION/);assert.match(html,/Session JSON/);assert.doesNotMatch(html,/private-cookie|private-at/);
  assert.match(c.accountSessionCopyControls({id:6},'fixture-class'),/SESSION未留存/);
});

test('Password status distinguishes uncertain submissions from no password and copies only confirmed values',()=>{
  const c=context();
  for(const [status,label] of Object.entries({uncertain:'设置未确认',failed:'设置失败',blocked:'设置受阻',already_set:'已有密码（未留存）',running:'设置中'})){
    const html=c.accountPasswordControl({id:5,password_setup_status:status,password_setup_candidate:'private-candidate'},'muted');
    assert.ok(html.includes(label));assert.doesNotMatch(html,/private-candidate|data-account-copy-secret|未设置（OTP登录）/);
  }
  const html=c.accountPasswordControl({id:5,has_gpt_password:true,registration_password:'private-password'},'muted');
  assert.match(html,/data-account-copy-secret="password"/);assert.doesNotMatch(html,/private-password/);
});

test('Both account tables render the shared password state control',()=>{
  for(const file of ['index.html','index_legacy.html']){
    assert.match(fs.readFileSync(path.join(base,file),'utf8'),/accountPasswordControl\(r,/);
  }
});

for(const [file,name] of [['index.html','_emailOtpCellV2'],['index_legacy.html','_emailOtpAction']]){
  test(file+': account API mailbox query appears without exposing a token-bearing URL',()=>{
    const c=context();const source=fs.readFileSync(path.join(base,file),'utf8');
    const start=source.indexOf('function '+name+'('),end=source.indexOf('\n}',start)+2;
    vm.runInContext(source.slice(start,end),c);
    const html=c[name]({id:5,email_source:'generic_api',code_url:'https://fixture/?token=private'});
    assert.match(html,/data-account-email-otp="5"/);assert.match(html,/API/);assert.doesNotMatch(html,/token=private/);
    c.EMAIL_OTP_CACHE.set(5,{code:'001234',at:'fixture'});
    assert.match(c[name]({id:5,email_source:'generic_api'}),/data-account-copy-email-otp="5"/);
    assert.doesNotMatch(c[name]({id:6,email_source:'unconfigured'}),/data-account-email-otp/);
    assert.match(source,/{% include 'account_session_controls.html' %}/);
    assert.match(source,/field === 'session_token' \? 'SESSION 已复制'/);
  });
}
