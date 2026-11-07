"""Qoder visible-browser signup and PAT creation.

Follows the proven QoderPilot flow (qoder.com/users/sign-up form, local slider
captcha, 6-digit mailbox OTP, PAT via the web session) on the app's fixed
dynamic residential exit. No stealth patches: real Chrome over CDP.
"""
import json
import re
import time
from urllib.parse import urlsplit

from core import qoder_mail
from core.grok_browser import GrokBrowserError, launch_browser, show_browser_window, verify_proxy_transport

SIGNUP_URL = "https://qoder.com/users/sign-up"
DASHBOARD_MARKERS = ("/dashboard", "/home", "/workspace")
ALLOWED_HOSTS = {"qoder.com", "www.qoder.com", "auth.qoder.com", "accounts.qoder.com"}
OTP_MAX_READS = 3
PAGE_LOAD_TIMEOUT_MS = 90000
INITIAL_SETTLE_MS = 6000
OTP_READ_INTERVAL = 30


class QoderBrowserError(GrokBrowserError):
    pass


def require_browser():
    from core.grok_browser import require_browser as _require
    return _require()


def _click(page, selectors):
    for selector in selectors:
        try:
            node = page.locator(selector).first
            if node.count() and node.is_visible() and node.is_enabled():
                node.click(timeout=5000)
                return selector
        except Exception:
            continue
    return None


def _fill(page, selector, value):
    try:
        node = page.locator(selector).first
        if node.count() and node.is_visible():
            node.fill(str(value))
            return True
    except Exception:
        pass
    return False


def _otp_form_visible(page):
    try:
        for node in page.locator("input.ant-otp-input").all():
            if node.is_visible():
                return True
    except Exception:
        pass
    return False


def _captcha_solved(page):
    try:
        state = page.evaluate("""() => {
            const wrapper = document.querySelector('#aliyunCaptcha-captcha-wrapper');
            const slider = document.querySelector('#aliyunCaptcha-sliding-slider');
            const body = document.querySelector('#aliyunCaptcha-captcha-body');
            if (wrapper && wrapper.offsetParent === null) return true;
            if (slider && slider.offsetParent === null) return true;
            if (slider && (slider.className.includes('success') || slider.className.includes('pass'))) return true;
            if (body && (body.className.includes('success') || body.className.includes('pass'))) return true;
            const icon = document.querySelector('#aliyunCaptcha-check-icon, [class*=success], [class*=pass]');
            return !!(icon && icon.offsetParent !== null);
        }""")
        return bool(state)
    except Exception:
        return False


SOLVER_JS = r"""
async () => {
  const bgImg = document.querySelector('#aliyunCaptcha-img');
  const puzzleImg = document.querySelector('#aliyunCaptcha-puzzle');
  const slider = document.querySelector('#aliyunCaptcha-sliding-slider');
  if (!bgImg || !puzzleImg || !slider) return {targetX:-1, error:'missing-elements'};
  async function getPixels(img) {
    const res = await fetch(img.src, { signal: AbortSignal.timeout(10000) });
    const blob = await res.blob();
    const url = URL.createObjectURL(blob);
    const tmp = new Image();
    await new Promise((r,j) => { tmp.onload=r; tmp.onerror=j; tmp.src=url; });
    const c = document.createElement('canvas');
    c.width = tmp.naturalWidth; c.height = tmp.naturalHeight;
    c.getContext('2d').drawImage(tmp,0,0);
    const id = c.getContext('2d').getImageData(0,0,c.width,c.height);
    URL.revokeObjectURL(url);
    return {w:c.width,h:c.height,d:id.data};
  }
  const bg = await getPixels(bgImg);
  const pz = await getPixels(puzzleImg);
  let pzMinX=pz.w,pzMaxX=0,pzMinY=pz.h,pzMaxY=0;
  for (let y=0;y<pz.h;y++) for (let x=0;x<pz.w;x++) {
    if (pz.d[(y*pz.w+x)*4+3] > 128) {
      if (x<pzMinX)pzMinX=x; if(x>pzMaxX)pzMaxX=x;
      if (y<pzMinY)pzMinY=y; if(y>pzMaxY)pzMaxY=y;
    }
  }
  const cw=pzMaxX-pzMinX+1, ch=pzMaxY-pzMinY+1;
  if (cw<=0||ch<=0) return {targetX:-1, error:'empty-puzzle'};
  const pzG=new Float64Array(cw*ch), pzM=new Uint8Array(cw*ch);
  let maskN=0;
  for (let cy=0;cy<ch;cy++) for (let cx=0;cx<cw;cx++) {
    const si=((pzMinY+cy)*pz.w+(pzMinX+cx))*4, di=cy*cw+cx;
    const a=pz.d[si+3]; pzM[di]=a>128?1:0; if(a>128)maskN++;
    pzG[di]=pz.d[si]*0.299+pz.d[si+1]*0.587+pz.d[si+2]*0.114;
  }
  const bgG=new Float64Array(bg.w*bg.h);
  for (let i=0;i<bg.w*bg.h;i++) bgG[i]=bg.d[i*4]*0.299+bg.d[i*4+1]*0.587+bg.d[i*4+2]*0.114;
  function blur(data,w,h){const o=new Float64Array(w*h);
    for(let y=1;y<h-1;y++)for(let x=1;x<w-1;x++)o[y*w+x]=(
      data[(y-1)*w+(x-1)]+2*data[(y-1)*w+x]+data[(y-1)*w+(x+1)]+
      2*data[y*w+(x-1)]+4*data[y*w+x]+2*data[y*w+(x+1)]+
      data[(y+1)*w+(x-1)]+2*data[(y+1)*w+x]+data[(y+1)*w+(x+1)])/16;
    return o;}
  const bgB=blur(bgG,bg.w,bg.h), pzB=blur(pzG,cw,ch);
  function ncc(src,sw,sh,tpl,tw,th,mask,maskN,offY){
    let bx=-1,bs=-2;
    const y0=Math.max(0,offY-10), y1=Math.min(sh-th,offY+10);
    for(let ox=1;ox<=sw-tw-1;ox++)for(let oy=y0;oy<=y1;oy++){
      let tm=0,sm=0;for(let i=0;i<maskN;i++){if(!mask[i])continue;
        const tx=i%tw,ty=(i/tw)|0;tm+=tpl[i];sm+=src[(oy+ty)*sw+(ox+tx)];}
      tm/=maskN;sm/=maskN;let tv=0,sv=0,cv=0;
      for(let i=0;i<maskN;i++){if(!mask[i])continue;
        const tx=i%tw,ty=(i/tw)|0,td=tpl[i]-tm,sd=src[(oy+ty)*sw+(ox+tx)]-sm;
        tv+=td*td;sv+=sd*sd;cv+=sd*td;}
      tv/=maskN;sv/=maskN;const ts=Math.sqrt(tv),ss=Math.sqrt(sv);
      if(ts<0.001||ss<0.001)continue;const n=cv/(maskN*ss*ts);
      if(n>bs){bs=n;bx=ox;}}
    return {bx,bs};}
  const nccR=ncc(bgB,bg.w,bg.h,pzB,cw,ch,pzM,maskN,pzMinY);
  let targetX = nccR.bx;
  if (targetX<=15) {
    const sx=new Float64Array(bg.w*bg.h);
    for(let y=1;y<bg.h-1;y++)for(let x=1;x<bg.w-1;x++)sx[y*bg.w+x]=
      -bgB[(y-1)*bg.w+(x-1)]+bgB[(y-1)*bg.w+(x+1)]-2*bgB[y*bg.w+(x-1)]+2*bgB[y*bg.w+(x+1)]-bgB[(y+1)*bg.w+(x-1)]+bgB[(y+1)*bg.w+(x+1)];
    const yS=Math.floor(bg.h*0.1),yE=Math.floor(bg.h*0.9),col=new Float64Array(bg.w);
    for(let x=1;x<bg.w-1;x++){let s=0;for(let y=yS;y<yE;y++)s+=Math.abs(sx[y*bg.w+x]);col[x]=s;}
    let bx=30,bsm=0;for(let x=30;x<bg.w-30;x++)if(col[x]>bsm){bsm=col[x];bx=x;}
    targetX=bx;
  }
  const bgRect=bgImg.getBoundingClientRect(), sRect=slider.getBoundingClientRect();
  const scale=bgRect.width/bg.w;
  const pzOff=pzMinX||0;
  const displayLeft=(targetX-pzOff)*scale;
  return {
    targetX, score:nccR.bs, method: targetX<=15?'gap-fallback':'gray-ncc',
    displayLeft: displayLeft<10?10:displayLeft,
    sliderX:sRect.x, sliderY:sRect.y, sliderW:sRect.width, sliderH:sRect.height,
    bgDisplayW: bgRect.width, bgNaturalW: bg.w
  };
}
"""


def solve_slider_local(page, max_attempts=5, stop_check=None):
    for attempt in range(1, max_attempts + 1):
        if stop_check is not None:
            try:
                if stop_check():
                    return True
            except Exception:
                pass
        try:
            page.click("#aliyunCaptcha-captcha-left", timeout=2000)
            page.wait_for_timeout(1500)
        except Exception:
            pass
        try:
            page.wait_for_function(
                "() => { const i=document.querySelector('#aliyunCaptcha-img');"
                " const s=document.querySelector('#aliyunCaptcha-sliding-slider');"
                " return i&&i.complete&&i.naturalWidth>0&&s&&s.getBoundingClientRect().width>0; }",
                timeout=15000)
        except Exception:
            return False
        try:
            result = page.evaluate(SOLVER_JS)
        except Exception:
            return False
        if not isinstance(result, dict) or result.get("targetX", -1) <= 0:
            page.wait_for_timeout(1000)
            continue
        display_left = max(10, result.get("displayLeft") or 0)
        sx = (result.get("sliderX") or 0) + 10
        sy = (result.get("sliderY") or 0) + (result.get("sliderH") or 0) / 2
        track = result.get("sliderW") or 0
        max_pz = (result.get("bgDisplayW") or 0) - 52
        if track <= 0 or max_pz <= 0:
            return False
        page.mouse.move(sx, sy)
        page.mouse.down()
        cx = sx + (display_left / max(max_pz, 1)) * track
        page.mouse.move(cx, sy, steps=10)
        page.mouse.up()
        page.wait_for_timeout(2500)
        if _captcha_solved(page) or (stop_check is not None and stop_check()):
            return True
        page.wait_for_timeout(800)
    return False


def create_pat(page, name="farm"):
    try:
        result = page.evaluate("""async ({name}) => {
            const exp = new Date();
            exp.setHours(23, 59, 59, 999);
            exp.setMonth(exp.getMonth() + 12);
            const csrf = window.csrfToken || '';
            const r = await fetch('/api/v1/me/personal-access-tokens', {
                method: 'POST',
                headers: {
                    'Content-Type': 'application/json',
                    'X-CSRF-TOKEN': csrf,
                    'x-requested-with': 'XMLHttpRequest'
                },
                credentials: 'include',
                body: JSON.stringify({ name: name + '-' + Date.now(), expires_at: exp.valueOf() })
            });
            return {status: r.status, body: await r.text()};
        }""", {"name": name})
    except Exception:
        return {"status": 0, "body": "", "error": "pat_fetch_failed"}
    if not isinstance(result, dict):
        return {"status": 0, "body": "", "error": "pat_response_invalid"}
    return result


def extract_pat_token(response):
    if not isinstance(response, dict) or response.get("status") != 201:
        return None
    body = response.get("body") or ""
    try:
        data = json.loads(body)
        token = data.get("token")
        if token and len(token) >= 64:
            return token
    except json.JSONDecodeError:
        pass
    match = re.search(r'"token"\s*:\s*"(pt-[A-Za-z0-9_\-]+)"', body)
    if match and len(match.group(1)) >= 64:
        return match.group(1)
    return None


def run(record, mailbox, signals, update, *, proxy_url=None):
    from playwright.sync_api import sync_playwright

    effective_proxy = proxy_url or record.get("private", {}).get("proxy_transport")
    if record.get("private", {}).get("proxy_prechecked") is not True:
        verify_proxy_transport(effective_proxy)
    process, debug_port = launch_browser(proxy_url=effective_proxy)
    issued = False
    otp_submitted = False
    attempts = 0
    sent_at = None
    next_read = None
    submitted_pat = ""
    try:
        with sync_playwright() as p:
            browser = p.chromium.connect_over_cdp(f"http://127.0.0.1:{debug_port}")
            try:
                context = browser.new_context()
                page = context.new_page()
                if not show_browser_window(context, page):
                    raise QoderBrowserError("无法展开本任务浏览器窗口，未访问官网或发码", reason="window_unavailable")
                update("running", "open", "已打开独立的普通浏览器；人机验证请在浏览器中人工完成")
                page.goto(SIGNUP_URL, wait_until="domcontentloaded", timeout=PAGE_LOAD_TIMEOUT_MS)
                try:
                    page.wait_for_load_state("load", timeout=60000)
                except Exception:
                    pass
                page.wait_for_timeout(INITIAL_SETTLE_MS)
                deadline = time.monotonic() + 600
                pat_submitted = False
                while time.monotonic() < deadline:
                    if signals.stop.is_set():
                        raise QoderBrowserError("用户已停止本邮箱任务", reason="user_stop")
                    if page.is_closed():
                        raise QoderBrowserError("注册浏览器已关闭", reason="browser_closed")
                    host = urlsplit(page.url).hostname
                    if host not in ALLOWED_HOSTS:
                        raise QoderBrowserError("进入第三方页面，已停止且未提交后续信息", reason="third_party")
                    if pat_submitted:
                        update("running", "save", "Qoder 会话已确认，保存 PAT")
                        return {"pat": submitted_pat, "pat_rw": ""}
                    if any(marker in page.url for marker in DASHBOARD_MARKERS):
                        update("running", "pat_create", "开始创建 Qoder PAT（不重发邮箱验证码）")
                        resp = create_pat(page)
                        token = extract_pat_token(resp)
                        if token:
                            submitted_pat = token
                            pat_submitted = True
                            update("running", "save", "Qoder PAT 已创建",
                                   profile_submitted=True, password_confirmed=True,
                                   registration_origin="browser",
                                   session_validation_status="browser_identity")
                            return {"pat": token, "pat_rw": ""}
                        update("manual_required", "pat", "PAT 尚未创建成功；请在浏览器完成登录后继续")
                        page.wait_for_timeout(1000)
                        continue
                    if _otp_form_visible(page) and not otp_submitted:
                        if next_read is None:
                            next_read = time.monotonic() + OTP_READ_INTERVAL
                            update("running", "email_code", "已进入邮箱验证码页；30秒后只读API，不重发")
                        code = signals.take_code()
                        if not code and mailbox.get("source") == "generic_api" and attempts < OTP_MAX_READS and time.monotonic() >= next_read:
                            if sent_at is None:
                                sent_at = time.time()
                            attempts += 1
                            try:
                                code = qoder_mail.read_once(mailbox, after_ts=sent_at)
                            except qoder_mail.QoderMailError as exc:
                                if not exc.retryable:
                                    raise
                            next_read = time.monotonic() + OTP_READ_INTERVAL
                        if code:
                            otp_submitted = True
                            update("running", "code_submitted", "已取得 Qoder 邮箱验证码；不记录内容",
                                   profile_submitted=True, password_confirmed=False)
                            boxes = page.locator("input.ant-otp-input").all()
                            chars = code.strip()
                            if len(boxes) >= 6:
                                boxes[0].click()
                                page.keyboard.type(chars, delay=80)
                            else:
                                page.keyboard.type(chars, delay=80)
                            page.wait_for_timeout(1500)
                            _click(page, ['button:has-text("Create account")', 'button:has-text("Verify")', 'button[type="submit"]'])
                            page.wait_for_timeout(8000)
                        elif attempts >= OTP_MAX_READS and time.monotonic() >= next_read:
                            raise QoderBrowserError("验证码未获取", reason="mail_timeout")
                        else:
                            update("manual_required", "email_code", "等待 Qoder 邮件码；最多读取3轮，每轮间隔30秒，也可手动输入")
                        page.wait_for_timeout(500)
                        continue
                    email_visible = page.locator('input[type="email"], input[name="email"]').first
                    if email_visible.count() and email_visible.is_visible() and not issued:
                        email_visible.fill(record["email"])
                        _fill(page, "#basic_firstName", "User")
                        _fill(page, "#basic_lastName", "Dev")
                        checkbox = page.locator("input[type=checkbox]").first
                        if checkbox.count() and checkbox.is_visible():
                            try:
                                checkbox.check(force=True)
                            except Exception:
                                pass
                        update("running", "email_submit", "提交邮箱表单一次；等待真实发码请求与验证码页")
                        _click(page, ['button:has-text("Continue")'])
                        issued = True
                        sent_at = time.time()
                        page.wait_for_timeout(4000)
                        continue
                    password_visible = page.locator('input[type="password"], input[name="password"]').first
                    if password_visible.count() and password_visible.is_visible() and issued and not otp_submitted:
                        password_visible.fill(record["private"]["password"])
                        update("running", "password_submit", "提交密码一次；等待验证码组件")
                        _click(page, ['button:has-text("Continue")'])
                        page.wait_for_timeout(4000)
                        continue
                    if issued and not otp_submitted:
                        captcha_visible = page.locator("#aliyunCaptcha-captcha-body, #aliyunCaptcha-sliding-slider").first
                        if captcha_visible.count() and captcha_visible.is_visible():
                            update("running", "captcha", "处理 Qoder 滑块验证码")
                            solved = solve_slider_local(page, stop_check=lambda: _otp_form_visible(page))
                            if not solved and not _otp_form_visible(page):
                                update("manual_required", "captcha", "滑块验证码未通过；请在浏览器人工完成")
                            page.wait_for_timeout(1000)
                            continue
                    if not issued and not otp_submitted:
                        update("manual_required", "open", "请在浏览器完成邮箱注册页操作；不自动处理人机挑战")
                    page.wait_for_timeout(500)
                raise QoderBrowserError("等待浏览器或人工操作超过10分钟，已停止；不自动重试", reason="timeout")
            finally:
                browser.close()
    finally:
        try:
            process.terminate()
            process.wait(timeout=5)
        except Exception:
            pass
