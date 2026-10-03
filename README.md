# weshell

CTF 靶场 / 教学场景下的 Webshell 管理端。单二进制，前端用 `embed` 内嵌，无外部依赖。

## 使用前提

**只能连接你自有或持有明确授权的教学/CTF 靶机。** 每次命令执行都会写入服务端审计日志。

## 边界

本项目**只实现**靶标管理与「HTTP 与马通信 + shell 命令执行与回显 + 靶机文件管理」；文件管理依赖 php-eval 型靶机。

刻意不做、也不会做：

- 流量加密、编码混淆、WAF 绕过、免杀
- 提权、持久化、内网横向
- 多马型适配（插件式套壳）

> 文件管理（列目录 / 读 / 写 / 删 / 上传 / 下载）已实现，但仅对 php-eval 型靶机生效，依赖管理端向靶机提交一小段 PHP 代码完成，仍是明文通信。

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

## HTTP 接口

| 方法 | 路径 | 说明 |
| --- | --- | --- |
| GET | `/api/kinds` | 支持的马型清单（含靶机侧样本） |
| GET | `/api/targets` | 靶标列表 |
| POST | `/api/targets` | 新建靶标 |
| GET | `/api/targets/{id}` | 靶标详情 |
| PUT | `/api/targets/{id}` | 更新靶标 |
| DELETE | `/api/targets/{id}` | 删除靶标 |
| POST | `/api/targets/{id}/exec` | 执行命令，body `{"command":"whoami"}` |
| GET | `/api/targets/{id}/fs/list?path=` | 列出靶机目录（php-eval 型） |
| GET | `/api/targets/{id}/fs/read?path=` | 读取文件，base64 回传（下载同此接口） |
| POST | `/api/targets/{id}/fs/write` | 写入/覆盖文件，body `{"path","base64"}`（上传同此接口） |
| POST | `/api/targets/{id}/fs/delete` | 删除文件/目录，body `{"path"}` |

## 靶标字段

| 字段 | 说明 |
| --- | --- |
| `name` | 显示名 |
| `url` | 马的 URL，需 http/https |
| `kind` | `php-eval` 或 `php-system` |
| `pass` | 参数名（即"密码"所在的键名） |
| `method` | `GET` 或 `POST` |
| `note` | 备注 |

## 载荷形态

`php-eval` 马提交的完整载荷（可在 Burp 里直接对照）：

```php
echo 'ws-<随机>';passthru('whoami 2>&1');echo 'ws-<随机>';
```

管理端按随机标记从响应中截取回显；命令默认追加 `2>&1`，便于把标准错误也显示出来。

`php-system` 马没有注入 PHP 的能力，因此直接提交命令原文，回显为响应体原文。
