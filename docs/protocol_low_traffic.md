# 协议注册省流与流量验证

这次改动针对 `D:\MY_PROJECT\AutoCodex\any-auto-register` 的 `protocol` 注册驱动。目标是减少认证主链路之外的请求，并让单次任务的 HTTP 消耗可以定位。**真实代理单账号低于 1 MB 尚待接入后实测**。

## 使用

在 WebUI「配置 → 注册方式」中选择 `protocol`，开启「协议注册省流」。默认预算 `1000000` 字节，即十进制 1 MB。也可以在项目 `.env` 中设置：

```dotenv
REGISTRATION_DRIVER="protocol"
PROTOCOL_LOW_TRAFFIC="True"
PROTOCOL_TRAFFIC_BUDGET_BYTES="1000000"
```

WebUI 保存后对新任务生效，已开始的任务固定使用开始时的模式。关闭省流开关即恢复完整模式，仍保留同样的流量计量，便于对照。浏览器驱动维持原有逻辑。

## 实际减少的请求

| 阶段 | 省流模式 |
| --- | --- |
| 登录页预检、CSRF、signin、authorize | 保留，读取真实响应和 Cookie |
| 匿名应用初始化 | 跳过 CES、匿名资料、定价等可选请求 |
| 邮箱 OTP、Sentinel、MFA、资料页、工作区 | 保留原有认证步骤 |
| OAuth callback | 逐跳执行，先让服务器写入当前会话 Cookie |
| 回调后跳转首页 | 已经过 callback 且收到 ChatGPT 会话 Cookie，才停止首页下载 |
| `/api/auth/session` | 必须请求并取得 AT；仅有 Cookie 不计为成功 |
| 登录后的应用初始化 | 跳过模型列表、system hints、会话列表、pins、资格诊断等可选请求 |
| NextAuth 错误页 | 记录认证失败，不额外下载完整错误 HTML |

公开 JS/CSS 缓存主要适用于浏览器；本次没有引入跨账号缓存，也没有复用账号 Cookie、OTP、OAuth 响应。独立运行的查活、2FA、套餐查询不继承注册省流模式。

注册后自动 2FA、Codex、套餐查询和 Flow 仍服从各自功能开关；它们会增加整次操作的实际消耗。对照单纯注册流量时，两组必须保持相同的功能设置，分别记录后置操作。

## 读流量记录

注册任务的「流量」列显示 `≈` 前缀，悬停查看口径。成功与失败任务都保存 `network_traffic`，日志末尾有 `[协议流量]` 汇总及下载量最大的 5 个路径。

- `upload_bytes` / `download_bytes`：libcurl 可见的请求体、请求头、压缩响应体及响应头。
- `decoded_download_bytes`：解压后正文长度，只作对照，不拿它当压缩下载量。
- `by_path`：按 Host/Path 聚合；不保存查询参数、凭据、请求头或正文。自动重定向归到原始调用，不伪造中间跳字节数。
- `unknown_size_request_count` / `automatic_redirect_count`：失败响应或自动重定向可能漏计。存在这类情况时，`within_budget` 可以为 `null`，表示尚不能确认预算。
- `within_budget`：诊断值，超过预算也不把已完成的注册改为失败。

计量覆盖注册线程里经过 `BrowserSession` 的会话，包括同线程的重试和后续流程。邮箱客户端、其他 SDK、异步后台查询，以及 TLS/IP/代理隧道开销不在这个 HTTP 估算值中。**最终成本以代理商双向流量差额为准。** 后台任务和并发注册的计数彼此隔离。

## 接入住宅代理后的验证

1. 在代理池填入购买的 HTTP/SOCKS5 地址和认证信息；如果代理商支持粘性会话，保持一次认证流程使用同一出口。
2. 并发设为 1，选定一个自己的测试邮箱，确认 IMAP/OTP 来源配置正确。
3. 记录任务前代理商累计上下行，运行一次完整模式，保存结果、日志及任务后的代理读数。
4. 对另一个测试邮箱开启省流，保持地区、并发和后置功能相同，再记录相同指标。
5. 比较成功/失败阶段、耗时、`network_traffic.by_path` 和代理商差额。失败任务的流量也纳入成本；确认后再逐步增加样本。

这里的本地回归只证明删减分支、认证回调边界、并发隔离及压缩字节计量正确，不证明远端注册成功率或真实单账号成本。

```powershell
cd D:\MY_PROJECT\AutoCodex\any-auto-register
.\.venv\Scripts\python.exe -m unittest tests.test_protocol_traffic
powershell -NoProfile -ExecutionPolicy Bypass -File .\webui.ps1 restart
```

## 参考

- 用户提供的 `D:\MY_PROJECT\AutoCodex\注册流量优化复现与使用教程.pdf`：请求分层、认证后收紧、区分网络与账单口径。
- [gpt-reg-review](https://github.com/jiangjin934/gpt-reg-review)：参考其独立任务计量及避免下载认证错误整页的思路；本次实现沿用本项目结构，未复制其注册状态机或源码。
