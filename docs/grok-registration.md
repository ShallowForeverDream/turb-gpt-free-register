# Grok 注册与独立账号库

## 入口与使用

侧栏顺序为“邮箱池、GPT账号、Grok账号、日志、设置”。新旧两套模板共用 Grok 页面。

1. 在“Grok账号”选择已有邮箱。GPT 已注册的邮箱可以继续注册 Grok；Grok 不会改写 GPT 账号、密码、Session 或邮箱池的 `used` 状态。
2. 保存 Grok 并发（1–4，默认1），勾选邮箱，确认邮箱使用授权后开始。每批最多50个；只有实际开始的任务才出现在日志里。
3. 默认“HTTP注册＋无窗口原生SDK”：业务接口使用独立HTTP Session，安全SDK需要已安装的普通Chrome/Edge/Chromium。SDK使用真实的无窗口运行时，不弹出可见注册窗口，不自动回退页面注册；这不是完全无浏览器的纯HTTP。原有“普通可见浏览器注册”仅在用户显式选择该驱动时使用。不自动购买邮箱、短信号码，不执行挑战求解、反检测补丁或代理轮换。
4. 暂停只暂停补充，继续使用当前计划；停止待启动任务只取消尚未准入的部分，不影响正在执行的浏览器。单项任务可以在日志弹窗中另行停止。
5. 成功后在 Grok 账号列表按需复制 SSO / SSO-RW / 密码。只有本次填写的密码被确认用于提交，才作为已知密码保存；人工修改或提交但无法确认的密码不会冒充为生成密码。

Grok 驱动独立于 GPT，当前不读取 GPT 的指纹、Cookie 或代理池配置。原生HTTP使用普通 Requests Session，不伪装浏览器指纹；尊重系统/环境已有的固定HTTPS代理及绕过规则，不读取 `.netrc` 凭据，不新选代理或自动回退直连。会话内冻结该路由；日志仅标记 `direct` / `existing_proxy`，不记录代理认证地址。API 取码仍使用现有 `GENERIC_API_PROXY`，未配置则直连；失败不会切换代理或关闭 TLS 校验。

## 独立原生协议驱动与真实边界

### 2026-11-03 上游实际启动测试

已将 HSJ-BanFan/grok-register-web 的完整仓库固定到
`218fc82a4535469c34a8b33b17478cae12731822`，使用独立虚拟环境、独立 SQLite 数据库，
在 `127.0.0.1:5086` 临时运行其 Flask 应用，通过真实的 `/api/register/start`
启动协议 worker（1 轮、1 并发、最多 1 次）。上游受版本控制的源码未修改。

**测试条件不是上游完整默认方案：**安装了上游 `requirements.txt`，但测试包装器禁用
curl 指纹模拟，让原有后端进入 Requests 回退路径，并使用真实的 Requests User-Agent；
同时禁用自动求解、浏览器回退、交付和激活。包装器仅允许读取注册入口及同源静态脚本，
禁止向服务发出业务 POST，首次 HTTP 拒绝后阻止后续网络访问。不导入真实邮箱凭据。
因此这是“应用启动与受限协议引导测试”，不是原样默认配置的完整注册验收。

实际结果：

- 控制台首页 HTTP 200，启动任务接口 HTTP 200；这些不代表 Grok 注册成功。
- 上游 worker 的第一条真实外网请求为 `GET https://accounts.x.ai/sign-up?redirect=grok-com`，
  返回 **403 / text/html**，CF-Ray 为 `a54a658ffecbf7bd-LAX`，无 `cf-mitigated` 标记。
- worker 原本在预热后还会再读取入口；测试保护阻止了首次拒绝后的第二次网络请求。
  随后 worker 以 `PROTOCOL_BOOTSTRAP` 失败，未选择邮箱。
- 原计划仍仅限 `advised_dill_2m@icloud.com`，但此次尚未提交该邮箱：
  发码、验码、建号、邮箱读取均为 **0**；没有取得或保存 SSO，独立库注册记录为 0。
- 现有 9 张业务表和 `.env` 的前后摘要一致，原 `127.0.0.1:5000` 服务未重启。
  临时服务已经关闭。上游入口分类专项 10 项离线测试通过，不替代线上注册验收。

对照结论：上游的 `accounts.x.ai` gRPC 发码/验码与 Next.js Server Action 建号，
和当前 `grok.com/api/auth/...` JSON 状态机确实不是同一路径；上游纯 HTTP 分支没有
当前 JSON 路径使用的 Castle 令牌，而在建号前需要 Turnstile 结果。不能把两个路径的
字段、安全上下文或令牌条件互相套用。此次没有成功的上游注册基线，入口 403 也不能解释
此前 G10 JSON 发码的 `400 / account:email-signup-unavailable`；该 400 的确切原因仍未查明。
没有据此更改线上业务协议或重放发码。

本地脱敏证据为项目根目录下 `.local.grok-upstream-runtime-20261103.json`；
测试包装器为 `.local.grok-upstream-harness-20261103.py`，启动日志和专项测试日志分别为
`.local.grok-upstream-runtime-20261103.log`、`.local.grok-upstream-startup-tests-20261103.log`。

上游固定版本源码：
[协议 worker](https://github.com/HSJ-BanFan/grok-register-web/blob/218fc82a4535469c34a8b33b17478cae12731822/core/registration/protocol_worker.py)、
[协议后端](https://github.com/HSJ-BanFan/grok-register-web/blob/218fc82a4535469c34a8b33b17478cae12731822/core/registration/backend.py)。

### 2026-11-03 人工成功抓包复核与 SDK 导航状态修复

对 `注册日志/grok_success1.log` 再次做了离线、只读的请求头/Cookie 名称/时间线复核（不打印任何值），
并与 G10 的实际上下文逐项对照：

- 人工成功流程在 `/api/auth/sso/check` 与发码请求前，已经进入过官网注册入口（`/sign-up`），
  且 Cookie 名称集合包含 `__Host-id-token-nonce`。G10 的 check/send 请求中该 Cookie 缺失。
- 人工成功的业务请求带 `sec-ch-ua*`、`sec-fetch-*`、`sentry-trace`、`baggage`、`priority` 等浏览器头；
  G10 只带 Requests 默认头 + Origin/Referer/User-Agent/Cookie。此前已确认不伪造这些头。
- 人工成功抓包中没有独立 Castle 域名请求，Castle 令牌由站内脚本生成；上游仓库的独立 Castle 外呼
  也不出现在本抓包中，不能据此推断令牌来源差异。
- G10 的核心确定性缺陷是 SDK 导航状态：令牌在首页上下文生成，而成功流程是在注册入口/认证组件
  打开后生成。现有代码只有在“需要找 Turnstile 配置”时才点击一次注册入口，导致 check/send 令牌
  可能缺少该导航状态。

已修复：`core/grok_native_sdk.py` 现在在第一次生成任何 Castle 令牌前，确保真实注册入口已打开一次
（不输入邮箱、不提交页面业务接口、不伪造导航状态）；之后所有令牌沿用同一真实导航状态。新增专项测试
覆盖“只打开一次”“入口缺失时明确失败且不伪造”。离线全量回归：Python 992/992、Node 102/102 通过。

边界：这是一项有证据的真实缺陷修复，但尚不能证明 `account:email-signup-unavailable` 的唯一根因；
需要下一次真实、有界的指定邮箱任务验证发码是否被接受。验证前不重放旧任务、不改历史结果。

### 2026-11-04 最终对照：官网页面自身同样被拒

用同一目标邮箱 `advised_dill_2m@icloud.com`，在真实无头 Chrome 中直接打开
`grok.com` 的站内注册组件，由**官网自己的表单和官网自己的 Castle SDK** 发出
`/api/auth/send-verification-code`，不经过本项目任何协议代码。结果：

- `/api/auth/session` 200，`/api/auth/oauth/id-token/nonce` 200；
- `/api/auth/sso/check` 200，返回 `{"enabled":false,"passwordSignInAvailable":false}`；
- 官网页面自身发码：**400**，响应
  `{"error":"Failed to send verification code","code":"account:email-signup-unavailable"}`。

这排除了本项目协议实现的 Castle 令牌、Cookie、nonce、UA、TLS、请求头、字段和传输问题：
官网页面与协议实现在同一出口、同一邮箱上得到完全相同的服务端拒绝。结合此前多次修复后的
复测（nonce/clearance 均已存在、真实浏览器 `fetch` 传输、CF_SITEKEY 正确解析），
当前可确认的结论是：**该邮箱在当前出口下被服务端判定为不可用注册，拒绝发生在发码资格判断层。**

本项目已完成的可验证修复：

- 解析官网真实公开配置 `CF_SITEKEY`，修复原先只匹配 `sitekey` 导致 SDK 初始化失败；
- 等待首页自然下发 `__Host-id-token-nonce` 与 `cf_clearance` 后再生成令牌；
- 在真实浏览器上下文中以 `fetch` 发送认证请求，避免 Python 客户端与 Castle 令牌跨运行时；
- 注册入口使用站内组件（`el.click()`），不跳转 `accounts.x.ai`（该域当前 403）；
- 修复系统代理在服务进程缺失环境变量时从注册表读取固定路由，不回退直连；
- 错误原因补齐 `sdk_security_context` 等明确码，不再落到“请查看浏览器阶段”。

仍不能把当前结果称为“注册成功”：目标邮箱没有收到验证码、没有建号、没有保存 SSO。
若需要继续验证，应更换一个未注册且服务端允许发码的邮箱，或确认该邮箱在 xAI 侧的实际状态；
不应继续对同一邮箱重复发码。以上对照证据为 `.local.grok-page-target-probe.json`。

### 2026-11-04 可见 Chrome 对照（排除自动化信号）

为排除无头/自动化标记影响，再用**真实可见 Chrome**（独立临时用户目录，
`navigator.webdriver=false`，不注入 Playwright 自动化参数）打开同一官网表单，
由官网自身发起 `send-verification-code`。结果仍是：

- `/api/auth/session` 200；
- `/api/auth/oauth/id-token/nonce` 200；
- `/api/auth/sso/check` 200；
- `/api/auth/send-verification-code` **400**，
  `{"error":"Failed to send verification code","code":"account:email-signup-unavailable"}`。

因此可确认：该邮箱在当前出口下被服务端拒绝注册发码，与无头浏览器、Playwright、
Castle 令牌、Cookie、nonce、UA、TLS、请求头均无关。证据：
`.local.grok-visible-chrome-probe.json`。

### 2026-11-04 同环境已知可用邮箱对照

在完全相同的可见 Chrome、出口、官网表单下，再测试人工注册成功过的
`axel-sellers-6o@icloud.com`：

- `/api/auth/session` 200；
- `/api/auth/oauth/id-token/nonce` 200；
- `/api/auth/sso/check` 200；
- `/api/auth/send-verification-code` **200 `{"ok":true}`**。

同环境、同域名、同请求结构下，`axel-sellers-6o@icloud.com` 发码成功，而
`advised_dill_2m@icloud.com` 发码 400。这证明差异来自目标邮箱在服务端的注册资格，
不是浏览器环境、出口、域名或客户端实现。证据：`.local.grok-known-good-email-probe.json`。

据此已在代码中增加明确分类：发码返回 `account:email-signup-unavailable` 时，
任务以 `protocol_email_unavailable` 停止并标记为 `blocked`，提示“请更换邮箱，
不要对同一邮箱重复发码”；不会再落入泛化的“官网拒绝原生HTTP请求”。

官网前端文案进一步确认该错误码的准确含义：`ACCOUNT_EMAIL_SIGNUP_UNAVAILABLE`
对应 “Email sign-up isn't available right now. Sign up another way.”
即该邮箱当前无法使用邮箱方式注册，而不是全站停服；应改用其他登录方式或更换邮箱。

### 2026-11-04 批次邮箱资格抽样

对同批 2026-10-28T21:08:15 的另一个 available 邮箱
`phi_78scads@icloud.com`，用同一可见 Chrome 表单做一次只读发码资格检查：
`send-verification-code` 同样返回 **400 `account:email-signup-unavailable`**。

同环境下 `axel-sellers-6o@icloud.com` 为 200，`advised_dill_2m@icloud.com` 与
`phi_78scads@icloud.com` 均为 400。当前证据表明：该批次 iCloud 邮箱存在服务端注册资格
差异，不是项目代码问题；不应继续用同批未知邮箱盲试。证据：
`.local.grok-candidate-eligibility.json`。

随后又对同批 available 邮箱 `willing-largess-4j@icloud.com` 做了一次官网可见 Chrome
发码检查，返回 **200 `{"ok":true}`**，说明该邮箱当时具备邮箱注册资格；但在几分钟后的
协议任务中同一邮箱发码返回 **400 `account:email-signup-unavailable`**。这说明发码资格
还受短时间重复请求/时间窗口影响，不能把一次 200 当作稳定可注册，也不能连续多次发码。
完整流程仍未打通，后续验证应在新的时间窗口、只发一次码。

`core/grok_protocol.py` 是当前 `grok.com/api/auth/...` JSON 链路的独立实现，不等于 HSJ-BanFan 的协议后端。本轮已实际复核上游 `protocol_worker.py` 和 `backend.py`；接口与依赖差异见下方“真实协议后端对照”，不能只看 `register.py` 或页面状态模块就声称已复现其方案。

- HTTP状态机按顺序处理入口预检、邮箱检查、发码、最多三轮30秒取信和验码、建号、受信任会话跳转、最终身份确认。只有官网明确返回验证码无效/过期，才在剩余轮次等待30秒读新码；已拒绝的同一码不重复提交，不增加发码次数。泛化400、挑战或连接异常不据此重放POST。建号请求前持久化不确定性标志；SSO须匹配同邮箱、同用户ID与当前本域Cookie，密码须由最终 `hasPassword=true` 确认。
- 每项任务私有记录驱动，默认 `protocol`，显式浏览器模式为 `browser`；旧任务未写驱动时保留旧浏览器语义。HTTP依赖检查不启动浏览器；首次需要安全上下文时加载SDK运行时，未安装普通浏览器时明确失败，不自动下载或替换浏览器。
- 原生上下文提供器为 `core/grok_native_sdk.py`。从本次官网页面只读解析公开 `CASTLE_PK` 和唯一Turnstile站点配置，不读取抓包令牌。配置懒加载时，只初始化空的官网认证组件，最多点击一次注册入口；不填邮箱、不执行页面注册。Castle采用官方npm发布的2.8.5版本浏览器SDK，通过固定CDN URL加载并校验由官方tarball完整性验证所得的SRI；Turnstile脚本使用官方实时URL，不缓存或修改。
- SDK使用当前任务独立的普通无窗口Chrome，保留原始运行时信号和 `HeadlessChrome` 标记，不伪造指纹、不改SDK、不关闭CSP、TLS或沙箱。HTTP采用SDK实际UA并同步当前任务的安全Cookie，不导入其他账号身份。每个check/send/create阶段新生成Castle令牌；验证组件只能返回官方真实完成的结果，不能用空值、历史值或伪造结果替代。
- SDK继续观察后续主文档导航，而非只检查首页200；若初始化认证组件后主文档被拒绝或出现明确挑战，立即停止，不能在403错误页继续生成令牌并标记SDK就绪。HTTP诊断同时记录SDK文档的状态和允许列表内路径，忽略图片等后台资源的单独失败。
- SDK上下文禁止POST邮箱检查、发码、验码和建号业务接口，即使用户误操作也不会从页面执行注册；业务调用始终由HTTP客户端完成。Cookie与原生令牌不回显、不写项目日志或账号payload；仅最终确认的SSO和已知密码按既有账号保存规则留存。
- 当前任务的匿名上下文按实际浏览器结果同步，包含 `grok_device_id`、`__cuid`、`__cf_bm`、`cf_clearance`、`__Host-id-token-nonce`、`i18nextLng`，保留域、路径、Secure、HttpOnly和主机限定属性；先完整校验再替换，清除浏览器已不存在的旧值。仅接收本次真实运行时正常取得的值，绝不导入抓包、其他任务或其他浏览器的 Cookie。认证响应更新匿名Cookie时回传同一SDK上下文，防止下一轮生成令牌又覆盖为旧值。OAuth nonce的存在不等于它是邮箱注册必需的CSRF凭据。
- 实际HTTP响应记录请求头名称、Cookie名称及重复名称、Origin/Referer校验、令牌生成至发出的间隔，以及实际发出Cookie/UA与SDK上下文是否一致；不记录原值或摘要。错误同时保留有界JSON结构与已知错误字段的脱敏信息，未知字段只记录类型。字段名相同、SDK能生成令牌或邮箱检查通过，都不能证明发码会被官网接受。
- [Castle 官方 Browser SDK 文档](https://docs.castle.io/docs/sdk-browser)将请求令牌定义为浏览器采集当前设备/行为后生成、按请求使用的短时令牌；其服务端SDK消费令牌，而非提供本项目可直接调用的独立生成接口。文档也不再支持以模拟DOM替代真实浏览器。提供器已接入真实浏览器SDK，但SDK生成成功不等于官网接受业务请求，也不能据此断言此前400的根因。加载失败不伪装成官网正在展示人机验证。
- HTTP入口明确返回 `cf-mitigated: challenge` 时记录 `protocol_challenge`；SDK配置/加载/运行错误会单独记录SDK阶段，不伪装成人机验证。若官方Turnstile触发交互回调，任务进入 `native_challenge`，保持原HTTP会话并等待明确确认；不会自动打开可见窗口。
- 只有用户点击“允许打开SDK验证窗口”并确认后，才恢复当前SDK存储上下文到普通可见运行时，显示原生验证组件。该窗口不填邮箱、不提交注册表单、不重发验证码。人工完成后继续原HTTP会话，重新生成本次建号所需Castle令牌，不复用过期令牌。不接入求解器，不自动点击或处理人机挑战。未得到确认则超时停止。
- 400 等业务拒绝、普通403、5xx和网络错误不是人机验证的充分证据。429无论是否带挑战标记均停止。若已经发码或提交建号，则不重新打开注册流程，以免重复发送或重复建号；保留明确失败/不确定结果。
- HTTP会话仅跟随本次响应给出的、允许域名的HTTPS `/set-cookie` 跳转，限制跳数，不向任意地址携带Cookie。跨域同步被拒绝时不重试该地址，仅可只读确认本域会话；不能因此重提注册。

完整链路为“HTTP业务＋原生SDK运行时”，不是浏览器零依赖的纯HTTP。原生SDK的加载与新令牌生成已做真实无窗口探测，但这不等于真实注册成功。线上验收必须另看指定邮箱任务日志中的发码接收、收信、建号和SSO落库，不能由本地夹具或SDK探测推断，也不保证目标服务接受自动化请求。

2026-11-02 本轮单邮箱协议任务 G9 已实际加载原生SDK、生成新令牌并通过邮箱检查，随后仅调用一次发码接口。官网返回 HTTP 400、`account:email-signup-unavailable`、`Failed to send verification code`，无挑战标记且未提供请求ID。任务已停止，没有进入取信、验码或建号，没有保存SSO，也没有自动开可见窗口。离线对照用户成功抓包确认各业务接口的JSON字段、类型、Origin及Referer一致，但通用拒绝信息不足以区分投递、邮箱资格或安全策略原因；不将猜测写成根因，不通过换邮箱、换线、伪装运行时或重放请求规避拒绝。

后续任务 G10 修复了匿名Cookie漏同步以及HTTP响应更新未回传SDK的问题，并记录了真实出站请求而非预备请求：SDK Cookie/UA匹配、Origin/Referer匹配，真实 `cf_clearance` 已携带，发码令牌生成至出站约15ms。发码仍返回相同400；实际响应正文只包含 `error` 和 `code`，没有隐藏的嵌套原因或请求ID。因此不能把缺失Cookie或本地等待直接认定为该400的根因。已有人工成功记录来自另一个邮箱，当前任务尚无同邮箱、同时段的人工成功对照。官网公开认证代码与成功记录的版本一致；公开客户端显示 `__Host-id-token-nonce` 来自Google One Tap的ID-token流程，不能自行把它当作邮箱注册的CSRF凭据来构造。HTTP业务仍由Requests发送，与人工浏览器的HTTP/2、客户端提示及行为信号不同；这些差异不等于已证明的拒绝原因，也不通过复制历史请求头或隐藏自动化信号消除。G10未进入取信/建号，未保存SSO，后续需同邮箱人工对照或服务方诊断，不自动重复发码。

仅显式浏览器模式：打开官网前，通过当前任务的浏览器会话恢复本窗口到正常状态并置前，再等待页面加载完成；不控制其他浏览器窗口，不去除自动化标志或修改浏览器安全设置。无法展开窗口时停止，不在不可见页面继续发码。

## 人工成功抓包校正

2026-11-02 用户提供的成功抓包记录显示，实际主流程来自 `https://grok.com/`，而不是旧 `accounts.x.ai/sign-up` 入口。已改为由普通浏览器打开 Grok 本域入口，并观察以下页面原生请求，不在 Python 中拼装或重放：

1. `/api/auth/sso/check`：检查邮箱已有登录方式。
2. `/api/auth/send-verification-code`：请求发码；返回 `ok=true` 只说明接口已接收，不等于邮件已经到达。
3. `/api/auth/sign-up/verify-email`：提交邮箱验证码。
4. `/api/auth/sign-up/create-account`：提交资料；成功响应下发 `sso` 和 `sso-rw`。
5. `/api/auth/session`：确认邮箱、用户标识和邮箱验证状态，再接受本任务 Cookie。创建响应中的初始布尔状态可能未就绪，不能只看该响应的默认标志。

这份记录中，发码与验证码提交相隔约30秒，不能据此认定投递精确耗时；仍按页面就绪后30秒、最多3轮取信处理。正常浏览器产生的请求令牌和人机验证字段保留原生行为，不复制抓包里的值、不生成替代令牌，也不绕过验证。

后台预取、遥测等请求失败不等同于注册接口失败。真实主文档、发码/建号请求的拒绝仍暂停并保留人工接管；429停止，不重试。若本域登录态已确认，不因随后跨域 Cookie 同步失败而重新提交注册。

### 参考项目复核后的修正（2026-11-02）

重新只读检查了 AaronL725 的 `registration_browser.py` / `registration_flow.py`（快照 `fa29079777ccc3157cf0b6e5438753f9994f7f89`）与 HSJ-BanFan 的 `core/register.py` / `core/registration/signup.py`（快照 `5bbd43bfcc0203449ccaa4155bde139fa8cb4430`）。两者都用于发现编排与表单处理差异，不将其 README 的成功描述当成本项目线上验收。

- **入口选择**：同时有登录、注册和邮箱注册按钮时，优先明确的邮箱注册入口；支持按钮和链接，忽略隐藏副本。同优先级有多个可用入口时交由人工，不随机点击。保留成功抓包确认的 `grok.com`，不照搬上游旧 `accounts.x.ai` 入口。
- **真实发码与表单点击分开**：点击邮箱表单只记录 `email_submit`，不据此声称发码成功或立即读历史邮件。原生流程要观察匹配邮箱的真实发码请求及 `ok=true`，并进入验证码页；失败/响应不明确时保留浏览器，不重复点击或重发。
- **验证码表单**：兼容一个聚合输入框或同一表单内六个可见可编辑的单字符框，忽略隐藏旧框。最后一个字符触发页面自动验码时，不再点击确认造成重复提交。普通提交支持省略 `type` 的默认按钮和明确命名的表单按钮，不将“重新发送”当作下一步。
- **身份绑定**：原生建号响应与后续 session 必须属于同一邮箱、同一 `userId`；session 请求实际携带的 SSO 还须匹配当前 Grok 本域 Cookie。仅页面出现邮箱文字不能替代原生身份校验；不混入跨域同步的 x.ai Cookie。
- **密码确认**：原生流程以内存核对实际建号请求中的密码是否等于本次候选，并等 session 的 `hasPassword=true` 才保存。不凭“输入框填过”推断，页面/人工改动密码时不误存候选值。
- **错误与恢复**：关键认证接口的非成功响应（包括5xx）或网络连接中断均暂停自动步骤，记录固定接口名和允许列表中的网络错误类型，不输出请求正文、Cookie 或私有 URL。提交结果不明确时不重放；429仍立即停止。

仅借鉴阶段拆分、单框/六格输入识别和注册结果与后处理解耦等普通工程处理；未引入第三方的挑战求解、反检测、自动重发或换邮箱/线路重试。

### 已有人工成功记录的 SSO 导入

`tools/import_grok_capture.py --file <用户提供的Burp文件> --email <指定邮箱>` 默认只做离线核验；明确添加 `--apply` 才写入本地。

- 仅接受指定邮箱的成功创建响应中、安全作用域正确的 SSO Cookie，并要求后续 `/api/auth/session` 使用同一 SSO、同一用户标识、匹配邮箱且已验证。
- 只导入 SSO / SSO-RW，不导入密码、邮箱验证码、人机令牌、其他邮箱或原始请求。不会重放任何抓包请求。
- 新条目明确标为“人工抓包导入 · SSO未在线复验”。抓包证明的是当时的成功，不保证当前会话未被撤销，不冒充自动化注册成功。
- 不覆盖不同的既有会话；同一会话重复导入幂等。原有自动化失败任务记录不改写。

## 邮件验证码

- 复用邮箱池已有的 `generic_api` 取码地址，不建立发码前基线，不点击重发。
- 本次浏览器进入验证码页并就绪后等待30秒，每次间隔30秒，最多读取3轮。接口401/403/429立即停止，不回退线路。
- 支持成功 JSON 的 `data.code`、`data.otp`、`data.verification_code`，或明确标识 xAI/Grok 的邮件主题/正文。
- 对于无邮件归属的旧 `data.code` 响应，仍不把六位数字盲目当作 Grok 码。对于邮件页面，先验证收件邮箱和 xAI/Grok 邮件主题或发件来源，再接受六位数字或字母数字验证码；内部规范为 `ABC-DEF`，填表去掉连字符。Grok 实际邮件的验证码也可能是六位数字，不能只按字符形式区分平台。
- API 连续3次未取得有效 Grok 码时报“验证码未获取”。其他邮箱来源暂通过日志弹窗人工输入。验证码只向当前等待任务传一次，不写入任务日志或账号列表。
- 验证码填写/提交后若未能确认下一步，保留浏览器供人工查看，不自动重复提交或重发。

旧 ICAPI 取码地址的抽测返回过 HTTP 200 但 `data.code` 为空，这不能证明原邮箱没有收到邮件。2026-11-02 用户在普通无痕浏览器中为唯一测试邮箱触发发码后，已从用户提供的邮件页面读取到该邮箱的 Grok 确认邮件，并提取六位数字码。此证据只证明这一个邮箱的真实收件和提取成功，尚未证明注册与 SSO 保存端到端成功。私有地址、Token、邮件正文和验证码不放在本文中。

### ICAPI 邮件页面映射

- 支持 `邮箱----HTTPS邮件页面链接` 或两列 CSV 文件。在 Grok 页点击“导入邮件页面链接”，只更新指定导入批次里提供的邮箱映射，不创建新邮箱，不修改注册状态，也不启动任务。
- 网页链接的 fragment Token 与旧取码 API Token 不同，不能自动推导。必须按邮箱匹配用户提供的每一条页面链接；重复邮箱/Token、非法域名、批次外条目或在途认证任务都会使整批操作回滚。
- `code_url` 改为已验证格式的邮件页面链接；旧值保存在私有 `previous_code_url` 中，不作自动回退。GPT 的查询/OTP 路径和 Grok 收件路径都通过同一适配器读取邮件页面的只读公共接口，而不是拿 HTML 当 JSON 解析。
- 使用 Bearer Header 请求固定的同源 `/api/v1/public/messages`，先验证返回的 `mailbox`、邮件收件人、平台和时间，再从最新匹配邮件的主题提取验证码；必要时读取该封邮件的详情并解析正文或去除脚本/样式后的 HTML。不遍历全部历史，也不请求邮件里的链接。
- 每轮最多一次列表请求及一次必要的详情请求；不改写代理、不跳过 TLS、不自动重发。登录/注册过程用本次发码时间排除历史邮件，不需要发码前基线。显式“只读查询”可读取当前最新邮件，不能据此保证历史验证码仍有效。
- “打开收件箱”仅在用户点击时按需返回页面链接；默认 Grok 列表不携带 Token。已有 GPT 账号的邮箱验证码查询继续按其邮箱池映射工作，不混用 Grok 邮件。

## 状态与恢复

- `grok_accounts` / `grok_jobs` 是独立 SQLite 表。`grok_accounts.email` 和 SSO 摘要唯一，防止重复账号/混合身份；共享邮箱池同时显示 GPT 与 Grok 状态。
- 同邮箱在途的 GPT 注册、2FA、查活、换邮箱、Codex 授权与 Grok 任务互斥，避免邮件码交叉消费。结果未确认的 Grok 任务不会自动重提建号。
- 原生流程只有本任务提交过建号、后续 session 确认同邮箱/同用户ID/同SSO，才保存账号；旧表单兼容路径仍要求页面精确显示本任务邮箱。既有账号提示不算新注册成功；SSO 也不代表模型 API、付费套餐或额度可用。
- 建号提交前持久化不确定性标志。提交后异常记为 `uncertain`；重启对旧进程运行中任务只标记中断，对待启动任务取消，不恢复发码或建号请求。
- 凭据仅通过显式接口返回，遵从现有 WebUI 鉴权或既有本机免登录设置，设置 `Cache-Control: no-store`；列表和日志不返回私有 payload。不自动改变 `.env` 中的访问控制配置。
- 日志页可选择 GPT/Grok，按邮箱/任务ID、状态和日期筛选。计划中任务不混入运行日志。
- 官网注册请求返回403，或返回明确的 `account:` 业务拒绝（如400 `account:email-signup-unavailable`）时，记录脱敏来源、错误码、请求ID和CF-Ray，保留浏览器并暂停自动步骤，由用户人工查看官网提示后明确确认继续。不自动刷新、重发或换线。429仍立即停止。图片等非交互资源的403只记录，不误判整个注册失败。

## 研究依据

### 真实协议后端对照（2026-11-02）

本轮通过GitHub公开API固定 HSJ-BanFan `master` 的提交 `218fc82a4535469c34a8b33b17478cae12731822`（提交时间 2026-11-02 19:09:04，北京时间），只读检查源码，未执行第三方注册机。

| 上游真实模块 | 已确认的行为 | 本项目处理 |
|---|---|---|
| `core/registration/protocol_worker.py` | 持有邮箱租约，依次发码、按本次请求时间收信、验码、处理验证、建号、取得SSO再处理交付 | 借鉴阶段边界和停止/落库语义；仍保留用户指定30秒、最多3轮的限制，不采用上游至少10轮收信 |
| `core/registration/backend.py` | `CreateEmailValidationCode` / `VerifyEmailValidationCode` 使用gRPC-Web，建号使用动态Next.js Server Action，入口为`accounts.x.ai` | 与当前`grok.com` JSON契约不同，不能将旧接口、静态action或省略Castle的假设直接塞进本域实现 |
| `build_protocol_session` | curl_cffi配置浏览器指纹伪装候选，默认UA为旧Chrome | 未迁入指纹伪装、候选轮换或历史请求头 |
| 外部Turnstile提供器 | 调用本地或第三方求解器；可配置浏览器回退 | 未迁入自动求解或自动浏览器回退；保留真实SDK与明确同意的人工验证 |

正常TLS验证、现有固定路由下，读取上游确切入口 `https://accounts.x.ai/sign-up?redirect=grok-com` 返回HTTP403（无挑战标记）。这次只有GET，没有提交邮箱、发码或建号。它证明上游入口在本机普通HTTP环境尚不可用，不证明上游在作者环境失败；更不构成当前JSON发码400的具体根因。不要用这次发现将错误分类为“验证码未收到”或伪造注册成功。

本轮同时按当前官网认证客户端修正混合SSO/密码路由：仅`enabled=true && passwordSignInAvailable=false`视为SSO-only。登录路由检查不证明账号存在或发码资格；明确的`account:existing-email`发码响应单独标为已有账号并停止，不读邮箱或保存候选密码。

只读研究并参考流程划分、公开表单选择器和邮件来源适配思路，没有运行第三方项目或引入其挑战求解/风控规避代码：

- [AaronL725/grok-register](https://github.com/AaronL725/grok-register/tree/fa29079777ccc3157cf0b6e5438753f9994f7f89)，本次复核快照 `fa29079777ccc3157cf0b6e5438753f9994f7f89`，MIT。重点是 `registration_flow.py`、`registration_browser.py` 的阶段编排、单框/六格表单、SSO 保存和提交结果未确认边界。前次研究快照为 `526341fac5ea`。
- [HSJ-BanFan/grok-register-web](https://github.com/HSJ-BanFan/grok-register-web/tree/5bbd43bfcc02)，研究快照 `5bbd43bfcc02`，MIT。重点是邮箱适配、Web 任务状态，以及注册成功与后处理失败分开记录。

## 离线验证

运行 `tools/run_offline_tests.py --suite all`：测试在临时源码副本、独立数据库及无真实凭据配置中执行，阻断外部网络。

新增测试涵盖平台数据隔离、双向收码互斥、队列并发/暂停/停止、鉴权与凭据脱敏、重复提交约束、重启恢复、代码格式和API只读行为。真实普通 Chrome 对 loopback 网站覆盖邮箱提交→验码→资料提交→邮箱身份核对→SSO保存；新旧两套模板通过实际浏览器加载检查。它们均不是 xAI 线上成功记录。

2026-11-02首次单邮箱线上测试在邮箱提交后收到 HTTP 403，旧日志未包含来源或结构化响应，不能判断具体拒绝原因。该次未进入API收码、未提交建号、未保存SSO。后续人工接管测试必须使用同一邮箱，不能从此记录推断注册成功。

### 2026-11-04 完整流程打通（browser 驱动）

sundae.standby-0e@icloud.com 在 browser 驱动下完整注册成功：发码 200 ok、30 秒后取得 Grok 验证码、验码成功、资料提交成功、浏览器登录态确认邮箱与验证状态，SSO / SSO-RW / 密码已保存，registration_origin=browser，session_validation_status=browser_identity。

根因与修复：Playwright launch() 会注入 --enable-automation，令 navigator.webdriver=true，官网拒绝邮箱注册发码；改为 subprocess 直接启动已安装 Chrome（无自动化标记）+ CDP attach，navigator.webdriver=false。注册入口用页面内 el.click() 打开站内认证组件，不再外跳 accounts.x.ai。建号后若 create-account 未返回 session，则通过页面自身 fetch 读取 /api/auth/session，并用 page.on(request) 捕获该请求实际携带的 SSO Cookie；只有邮箱匹配、emailConfirmed=true、请求 Cookie 与响应后 Cookie 一致才保存。

该验证只使用一个邮箱、一次发码，未自动重发。lignin.sights_7c@icloud.com 的建号已提交但结果未确认，保持 uncertain，未自动重提。


## 2026-11-04 页面重构与官方 Grok CLI auth.json

- “Grok账号”页只显示已注册的 Grok 账号，视觉与 GPT账号页共用 `accounts-panel-v2` / `accounts-table-v2`；已移除“待选邮箱”和“最近Grok任务”。
- “邮箱池”页顶部拆为两个独立卡片：“GPT 注册”使用 `/api/jobs/*`，“GROK 注册”使用 `/api/grok/*`。Grok 并发、驱动、暂停/继续/停止、邮件页面链接导入和队列状态均位于 Grok 卡片内。
- Grok 日志仍进入“日志”页，通过“平台 = Grok”筛选；任务行使用 `G#<id>`，与 GPT 的 `#<id>` 区分。
- 注册成功后自动尝试官方 Grok CLI OIDC 设备授权：`auth.x.ai` device code → 普通浏览器确认 → token 轮询。成功后将官方 `auth.json` registry（key 为 `https://auth.x.ai::b1a00492-073a-47ea-816f-4c329264a828`）存入账号 payload，并在 Grok账号页提供“下载 auth.json”；授权失败只标记可重试，不影响已完成的 Grok 注册与 SSO。
- 实测：`sundae.standby-0e@icloud.com`、`upbeats-shrill5s@icloud.com` 均完成 CLI 授权并下载到含 `key`、`refresh_token`、`expires_at`、`oidc_issuer`、`oidc_client_id` 的 auth.json；未在日志或文档中记录 token 值。
- 重启恢复：`pending` 任务重新入队但保持“暂停补充”，需用户点“继续注册”；重启时丢失线程的 `running/stopping` 任务标记失败，不自动重放注册请求。


## 2026-11-05 GPT 账号页与邮箱池清理

- GPT 账号页只显示有可用凭据（access_token / session_token / session_json）的账号；历史“Imported Registered Email”占位和 7 条无 token 的半成品注册记录已清理，共删除 208 条，并将对应邮箱恢复为 available。
- “导入选中邮箱”不再创建 GPT 账号占位；该按钮已改为“清理无效账号”，调用 `/api/accounts/cleanup-unusable`，只删除无凭据记录并释放对应邮箱，不影响有 token 的正常账号。
- 邮箱池新增“GPT 注册中”筛选（`gpt:processing`）。`GPT 未注册`只显示 status=available 且无活跃任务/未被 registration_status=disabled 的邮箱；已 used/failed/disabled 或同邮箱有 pending/running/stopping 任务的不再显示为“未注册”。
- 原因：此前 200 个占位账号把邮箱标记为 used，导致邮箱池仍显示为“GPT 未注册”但实际无法领取；现已修复为一致状态。
