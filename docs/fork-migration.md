# 旧项目功能迁移记录

本 fork 基于 `myfanhua/turb-gpt-free-register` 的 `3a58d0e1d58b816b6503ae8f7a2680b78cb73ec2`，于 2026-09-24 核对上游。
对照对象是原 `any-auto-register` 源码及其未提交的本地改动。旧项目采用 FastAPI / SQLModel / React，新项目采用 Flask / 原生 JS / SQLite，不直接覆盖文件或混用数据库。

## 迁移取舍

| 旧项目功能 | 新项目现状 | 处理 |
| --- | --- | --- |
| Windows 启动脚本、解释器选择 | 提供 Bash 管理脚本，没有 Windows 对等入口 | 新增 `webui.ps1` / `webui.cmd`，支持解释器、Conda、启停、状态及日志 |
| 日志一键复制 | 两套界面都有日志查看，缺少复制按钮 | 适配两套界面，共用日志组件，增加下载和跟随开关 |
| 任务历史批量删除 | 已有 `/api/jobs/delete-bulk`，保护运行中任务 | 保留上游 |
| 账号批量管理、搜索、筛选、导出 | 已覆盖，另有归档、备注、日期和套餐筛选 | 保留上游 |
| Outlook 邮箱池与 MFA 管理页面 | 已有对应邮箱管理、2FA 状态及操作界面 | 保留上游，不搬运旧协议实现 |
| 仪表盘统计 | 已有 `/api/summary` 和界面统计 | 保留上游 |
| 多平台插件、第三方服务自动拉起 | 旧项目专用架构，新项目以单一业务为中心 | 本轮不引入，避免额外端口、依赖及后台进程 |
| 注册协议、代理轮换、验证码及风控规避相关代码 | 与本轮本地管理功能无关 | 不迁移、不验证这些流程 |

## Windows 使用

先按上游说明准备好依赖，脚本本身不会安装软件。PowerShell：

```powershell
.\webui.ps1 start -OpenBrowser
.\webui.ps1 status
.\webui.ps1 logs
.\webui.ps1 stop
.\webui.ps1 restart -Python 'C:\path\to\python.exe'
# 使用旧环境时，需要先确认其满足新版 requirements.txt。
.\webui.ps1 start -EnvName any-auto-register -Port 8000
```

CMD 可用 `webui.cmd start`。默认绑定 `127.0.0.1:5000`；解释器优先级为显式 `-Python`、显式 `-EnvName`、项目 `.venv`、PATH 中的 Python。

脚本使用 `run/webui-<端口>.json` 记录进程，核对创建时间、解释器和当前目录的 `web.py` 后才停止；不会根据端口号停止其他程序。Windows 虚拟环境可能由启动器再拉起一个实际服务进程，脚本会核对并管理该子进程。后台启动不弹终端窗口。启停命令按项目及端口互斥。

输出分别保存在 `logs/webui-<端口>.log` 和 `logs/webui-<端口>.error.log`，启动时覆盖上一轮输出；需要保留时先另存。授权码沿用上游 `.env` 的配置。未配置时，上游可能把临时授权码写入启动日志。

`stop` 会终止后台进程，不会等待业务任务完成；有进行中任务时，请先在界面结束任务。只有本脚本启动的进程受其管理，直接启动的 `python web.py` 仍由原终端管理。

## 日志查看

现代和 Legacy 界面的任务日志窗口均支持复制、下载 `job-<ID>.log`、暂停跟随。向上滚动自动暂停跟随，勾选后回到底部；刷新失败保留已显示内容并提示错误。快速切换任务时丢弃旧请求返回的日志，避免串行显示错误。

复制和下载针对当前接口返回的日志快照，不额外读取服务器文件；内容未经脱敏，分享前自行检查。两个界面共用工具栏和脚本模板，避免后续修复不同步。

## 验证与数据边界

```powershell
node --test tests/test_job_log_viewer.cjs
python -m unittest discover -s tests -p test_windows_webui_launcher.py -v
```

日志测试使用内存中的模拟接口；Windows 测试在带空格及中文的临时目录启动本地 HTTP 测试服务，覆盖启停、重启、端口占用、PID 复用保护和启动失败清理。它们不运行项目注册或外部授权流程。

2026-09-24 验证结果：6 项日志交互测试及 4 项 Windows 测试通过；两套完整模板渲染后的 JavaScript 语法检查通过；内置浏览器中检查了离线日志组件的按钮、跟随开关和长日志布局。未进行完整业务端到端测试。

2026-09-25 补充：在项目 `.venv` 安装 `requirements.txt` 后实测 WebUI 启动，`/login` 返回 HTTP 200。另增 Windows 虚拟环境进程启动与停止回归测试。

本轮仅迁移源码功能，旧项目数据库、配置、邮箱凭据、Token 和运行日志均未导入或上传。旧备份保持原状。

后续同步上游使用 `git fetch upstream`，再审阅并合并 `upstream/main`；`origin` 指向个人 fork。
