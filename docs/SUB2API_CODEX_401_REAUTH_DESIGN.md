# Sub2API Codex OAuth 401 自动重新授权开发设计

## 1. 目标

为管理员显式启用的 OpenAI/Codex OAuth 账号增加自动恢复流程：Sub2API 每 5 分钟检查账号的上游认证状态；确认账号因授权失效而进入 401 状态后，关联该账号的登录资料，排队执行一次正常登录与 OAuth 重新授权；成功后只更新该账号的 OAuth 凭据，并恢复账号调度。

本设计以 Sub2API v0.2.8 为代码基线。第一阶段只覆盖 OpenAI/Codex OAuth 账号，不扩展到密码/API Key 账号或其他平台。

## 2. 术语与现有机制

- **Access token 刷新**：用现存 refresh token 换取新的 access token。Sub2API 已有 OAuth 刷新路径，应继续负责正常过期续期。
- **重新授权（reauth）**：当 refresh token 或整段登录会话已失效时，使用账号登录流程重新完成 OAuth，取得新的 OAuth 凭据。它不是普通 refresh 的同义词。
- **401 候选**：必须是 Sub2API 能归因到某个上游账号的认证失效状态；客户端 API Key 错误、网络失败、限流等不能触发登录。
- **SMS 参考项目**：[maile456/codex-auto-sms-receiver](https://github.com/maile456/codex-auto-sms-receiver) README 描述了登录/OAuth 授权、验证码处理、凭据管理和 Sub2API 格式导出。当前 README 没有描述 Sub2API 账号定时同步或可供 Sub2API 调用的重授权 API，因此集成前必须检查其实际接口；不能把“可导出 Sub2API 文件”视为“已支持自动回写”。

相关现有代码入口（实现前再次核对 v0.2.8 分支）：

- `backend/internal/handler/admin/account_handler.go`：管理员账号 OAuth 凭据刷新和应用路径。
- `backend/internal/repository/openai_oauth_service.go`：OpenAI OAuth refresh-token 请求。
- `backend/internal/config/config.go`：已有 OAuth 401 调度冷却配置。新功能的扫描周期、重授权冷却和普通调度冷却需分别定义，避免混用。

## 2.1 阶段 0 现状审计（2026-09-23）

审计基线：Sub2API tag `v0.2.8`，当前自定义分支审计时 HEAD 为 `7af31227d1dbc7dd4caa6efa85ce9a3bfb7a06e5`。本节记录现有实现，不代表新增行为。

| 上游结果/条件 | 当前 Sub2API 行为 | 是否进入普通 refresh 扫描 |
| --- | --- | --- |
| OpenAI OAuth 401，错误码 `token_invalidated` / `token_revoked` | 清 token cache，调用 `SetError`，账号变成 error 且不可调度 | 否；候选查询只选 `status='active'` |
| OpenAI OAuth 401，响应 `detail=Unauthorized` | 调用 `SetError`，按永久认证错误处理 | 否 |
| OAuth 401，但无 refresh token | 调用 `SetError`，按不可自动 refresh 处理 | 否 |
| 其他 OAuth 401，且有 refresh token | 清 token cache；保持 active 并记录临时不可调度原因，默认冷却 10 分钟 | OpenAI OAuth 账号按持久化的 `OAuth 401:` 原因强制走一次现有 refresh-token 路径；其他平台仍遵循各自刷新策略 |
| 非 OAuth 账号 401 | 调用 `SetError` | 否 |
| refresh token 刷新失败且被分类为不可重试 | 常规 refresh 路径可调用 `SetError` | 后续不再进入 active-only 候选 |

当前后台 token refresh 服务默认每 5 分钟扫描一次（配置可调整）。OpenAI OAuth 账号若 `expires_at` 尚在刷新窗口外，但已有持久化 `OAuth 401:` 状态，现会强制进入一次既有 refresh-token 流程；没有 refresh token、其他平台/API Key、非 401 临时状态和永久 `error` 账号不会命中此分支。它不是上游健康探测器，也不是完整登录重授权器。管理端已有的“刷新账号 token”只使用账号现存 refresh token，不会执行重新登录。

因此，现有 refresh 定时器已能处理“token expiry 尚远但被上游拒绝”的一次标准刷新，但不能满足“refresh 不可恢复时自动重新登录”。阶段 4 仍需独立的结构化任务状态；不能把错误文本中任意出现的 `401` 当触发条件。临时 401 冷却、普通 refresh 重试冷却、人工永久 error 和重授权任务状态必须保持各自语义。

阶段 3 的首个代码改动：当 OpenAI OAuth 账号仍为 `active`、持久化原因以 `OAuth 401:` 开头且有 refresh token 时，现有周期扫描会绕过 `expires_at` 门槛，执行一次标准 refresh-token 流程。缺 refresh token、其他临时状态和 `error` 账号均不走这条分支。此改动复用原有扫描器、锁和 refresh API，不新增 goroutine、轮询器或外部依赖；它只解决“上游已拒绝但本地 expiry 尚未来到”的漏刷新，不等同于自动登录。结构化任务队列、不可恢复 refresh 后的网页登录触发与 worker 仍未实现。

凭据写回方面，现有管理刷新路径在成功后构造 OAuth credentials、通过账号更新服务保存并清 token cache；清理 error 的路径另行调用。自动重授权写回应采用账号 ID + 凭据版本/旧凭据条件做事务化更新，防止任务覆盖管理员刚更新的凭据，并且只更新认证字段与必要的调度状态。验收时需逐字段确认用量窗口、累计用量和历史使用记录不变。

## 2.2 阶段 1 SMS 项目接口审计（2026-09-23）

检查对象：`maile456/codex-auto-sms-receiver`，固定审计 commit `1366a7156068d3172301c1c3487a23d3a2437458`。以下结论对应该 commit，不自动代表上游后续版本。

### 许可和运行依赖

- 主项目及仓库内两个 vendor 项目均附 MIT LICENSE；若复用或复制代码，应保留各自版权和许可证文件，并记录对应上游 commit。
- 主程序是 Python/Flask；登录任务依赖 `curl_cffi`、`pyotp` 等库。`requirements.txt` 使用版本范围而非完整锁定清单，正式集成前需独立锁定依赖并审阅更新来源。

### OAuth、验证码和 worker

- 项目调用 vendor 中的 Codex OAuth 入口处理已有账号登录，支持密码 + TOTP。遇到重复手机号验证时，源项目跳过该账号当前的重新授权任务；手机号验证仍由人工完成，或由 HeroSMS（简称 HSMS）调用手机接码服务接口完成。这不是绕过验证，也不是跳过验证后继续登录。Sub2API 不集成源项目的 HeroSMS 接码实现；首版只保留账号已有的密码 + TOTP 登录资料，不引入邮箱库存或接码服务配置。
- `CodexJobManager` 将任务/流水线状态写入本地 `pipeline-state.json`，通过独立 worker 进程执行任务；提供超时、有限重试、暂停/停止和并发限制。遇到重复手机号验证时，跳过的是该账号当前的重新授权任务，不是绕过手机号验证；后续由人工完成手机验证，或由 HeroSMS 完成验证。任务队列与租约是单机进程内机制，不是可供 Sub2API 多实例共享的持久队列。
- 登录成功后 OAuth 文件保存在该项目自己的凭据目录。worker 结果队列传递状态、脱敏消息和文件路径，不传递完整 token；项目没有把凭据安全地原子写回指定 Sub2API 账号的逻辑。

### API/CLI 边界

| 接口 | 实际行为 | 对 Sub2API 的适配性 |
| --- | --- | --- |
| `POST /api/seller/credentials/relogin` | 接收 SMS 项目自己的邮箱库存 ID，排入该项目 reauth 流程 | 不是 Sub2API `account_id`；本机 WebUI 路由，不应直接暴露或作为跨服务契约 |
| `POST /api/v1/integration/accounts/submit` | 按邮箱启动普通账号任务；已有本地凭据或活动任务时返回 `started=false` | 不支持 reauth 模式；旧凭据文件存在时也不会因此重登，且不回传 token |
| `GET /api/v1/integration/accounts/status` | 按邮箱返回本地任务/凭据就绪状态 | 只给状态，不给新凭据，也没有 Sub2API 账号绑定 |
| `app.py` 命令行 | 启动本机 WebUI，可设 host/port/debug | 没有独立的 reauth CLI/worker RPC 命令 |

WebUI 默认绑定 `127.0.0.1`，`create_app` 强制 loopback；这些 API 没有面向公网服务的认证与权限契约。因此不通过 Caddy/反向代理公开，也不把它们当作 Sub2API 的现成远程接口。

### 秘密存储和集成决定

- `MailboxStore` 将登录资料保存在 `mailboxes.json`，其中可能包含邮箱访问 token、密码、TOTP/取码资料；当前实现为明文 JSON。OAuth 凭据另存为本地文件。日志虽有脱敏逻辑，原始日志仍按项目说明视为敏感数据。
- **阶段 1 决定：采用 Sub2API 管理、私有重授权 worker 执行的边界，不直接调用 SMS WebUI API。** 这不是把登录工作都交给 Sub2API；参考项目提供登录/OAuth 重新授权能力以及遇到重复手机号验证时跳过该账号当前任务的处理方式，人工或 HeroSMS 可另行完成手机号验证。Sub2API 负责账号级编排与受控写回：

| Sub2API 负责 | SMS 项目能力负责 |
| --- | --- |
| 识别并持久化目标账号的 OAuth 401；筛选启用自动恢复的账号；按稳定 `account_id` 绑定登录资料并创建幂等任务 | 使用绑定账号的密码 + TOTP 执行正常 OAuth 重新授权；返回结构化结果与新 OAuth 凭据 |
| 5 分钟扫描、任务冷却/状态、管理界面与权限；校验返回凭据对应的账号 | 隔离运行登录 worker，处理执行超时、密码 + TOTP 登录和脱敏错误 |
| 在事务中仅更新目标账号的认证字段、清认证错误并失效 token cache；保留该账号的用量与其他设置 | 不直接访问或整行覆盖 Sub2API 数据库；额外确认/人工输入时返回待处理状态 |

**表述更正（2026-09-24）：** 参考项目遇到重复手机号验证时，跳过的是该账号当前的重新授权任务，并非绕过身份验证或跳过验证后继续登录。手机号验证仍由人工完成，或由 HeroSMS（简称 HSMS）调用手机接码服务接口完成。Sub2API worker 不复用参考项目的任务处理代码或 HeroSMS 接码集成；它运行正常的官方 OAuth 登录/授权步骤，一旦遇到手机号验证，就将该账号当前任务标记为 `phone_verification_required` 并释放 worker slot。该账号任务结束不影响队列中的其他账号任务；管理员在外部完成验证后再更新 OAuth 凭据或重新入队。worker 不询问或自动提交手机号/短信验证码，也不自动重试当前任务。

**明确排除项：SMS/接码实现不整合进 Sub2API。** 不移植参考项目的 worker，也不移植 HeroSMS 取号、发码、轮询实现；不加入接码服务 API Key、国家/价格配置、相关依赖或管理界面。这不代表绕过手机号验证：首版只支持正常 OAuth 页面上的密码 + TOTP 登录；若遇手机号验证，当前账号任务以 `phone_verification_required` 结束，留给管理员通过外部流程人工或使用独立接码服务完成验证。若需要额外邮箱验证码则停止并转人工处理。

- SMS 现有 API 没有上述凭据回传与 Sub2API 账号绑定能力，所以要复用其重授权执行模块并适配成 Sub2API 管理的私有 worker；不能照搬其明文 mailbox store。任务状态不得包含密码、验证码或 token 原文。
- worker 的进程/部署形式与 RPC schema 在阶段 5 细化；登录资料加密与密钥方案见阶段 2 草案 2.3。

### 2.4 toSub2 传输层整合修正（2026-09-24）

此前“TLS 指纹/Cloudflare 求解不整合”的表述已修正。Sub2API 现在包含一份
`poxiao33/toSub2` v1.7.1 的受控运行时子集，位置为
`backend/resources/tosub2-transport/`。整合范围只覆盖 OAuth HTTP transport 和
Cloudflare challenge 会话，不整合 toSub2 的邮箱库存、短信、HeroSMS/HSMS、批量
注册或本地 WebUI。

实现分为两层：

1. Go 侧 `tosub2_transport.go` 负责启动短生命周期 NDJSON helper、设置代理和
   Chrome TLS profile、限制帧/请求/响应大小、识别 challenge、发送求解请求并重放
   原始 OAuth POST。helper 进程不是 shell 命令，错误输出丢弃，Sub2API 日志不写入
   密码、Cookie、Authorization 或 token。
2. Python `curl_cffi` helper 复用同一 Session、代理出口和 TLS impersonation；
   `cloudflare-ctf` 的父 challenge/Turnstile 子 challenge 在同一 Session 中运行。
   返回 `cf_clearance` 后只重放一次原请求；求解失败、超时、非法 JSON 或超限响应
   都转为普通 OAuth 失败，不进入无限重试。

该路径默认关闭。只有显式设置
`OPENAI_OAUTH_TOSUB2_TRANSPORT_ENABLED=true` 且运行环境具备 Python/curl_cffi、
Node.js/jsdom 时才启用；否则继续使用现有 Go `req` 客户端。Chrome profile 默认
为 `chrome146`，可用 `OPENAI_OAUTH_TOSUB2_TLS_PROFILE` 覆盖。OAuth 请求的代理
仍来自账号绑定代理，helper 不读取或复制登录资料；每个请求的 helper 结束后其
内存 Cookie/TLS 状态随进程销毁。

仓库 `deploy/Dockerfile` 提供 `INCLUDE_TOSUB2_RUNTIME=true` 构建开关，启用后才会
在镜像中安装 `python3`、`curl_cffi`、Node.js 和 `jsdom`；默认构建与官方镜像不
增加这组运行时依赖。使用该 transport 前必须先将 Compose 的 `image` 指向这个
自定义镜像，再开启对应环境变量。

注意：当前 provider 已改为使用同一 helper Session 执行官方协议登录：ChatGPT
CSRF/signin、密码 + TOTP、workspace 选择、Codex session/select 和 OAuth 回调。
网页登录不再启动 headless Chromium，而是通过同一 helper Session 访问官方协议
接口。每个协议请求都会检查 Cloudflare challenge；若响应包含可执行挑战，先在
同一 Session 中运行 solver，再用同一代理、TLS 指纹和 Cookie 重放原请求。挑战仍
存在时分类为 `security_challenge_required`。普通 `auth.openai.com/log-in` HTML
页面仍按登录流程错误处理，不会误判为 Cloudflare。手机号、邮箱验证码和其他
需要人工完成的步骤仍按 `needs_input`/`phone_verification_required` 分类，不由
helper 代提交人工验证。

## 2.3 阶段 2 数据模型与密钥方案草案（2026-09-23）

本节仍是 Ent schema/SQL migration 的评审设计；OAuth transport 的运行时代码已在
`backend/internal/repository/tosub2_transport.go` 实现，资料 schema 与队列 schema
按本节继续验收。

### 已有加密能力审计

- `backend/internal/repository/aes_encryptor.go` 已实现 AES-256-GCM，随机 nonce 与密文/tag 拼接后 Base64 编码；可复用其算法实现。
- 当前 `NewAESEncryptor` 只读取 `totp.encryption_key`。若该配置为空，`config.Load` 会在进程内生成随机值，不保证重启或多实例间一致；因此不能直接拿缺省 TOTP key 加密需要长期保留的重新授权资料。
- `security_secrets` 目前用于持久化 JWT signing secret，数据库中可直接读取其 value。它不是外置 KMS，也不适合作为保护数据库内登录资料的主密钥。

### 建议 schema

| 表 | 关键字段 | 约束/用途 |
| --- | --- | --- |
| `account_reauth_profiles` | `account_id`、`enabled`、`secret_ciphertext`、`key_id`、`profile_version`、时间戳 | `account_id` 唯一且关联 `accounts.id`；只允许绑定 OpenAI OAuth 账号；密文仅含该账号的登录密码与 TOTP 种子；默认关闭 |
| `account_reauth_jobs` | UUID `id`、`account_id`、触发原因、状态、尝试次数/上限、`next_run_at`、租约字段、profile 版本、凭据指纹、脱敏错误码、开始/结束时间 | 持久化并发任务；部分唯一索引保证每个账号最多一个活动任务；凭据指纹只用于完成时条件写回，不保存 token 原文 |
| 系统设置 | 全局开关、检查间隔、最大并发、失败冷却/退避 | 存普通配置，不包含加密主密钥；默认关闭、间隔 5 分钟、并发 1 |

任务状态建议：`queued`、`running`、`needs_input`、`succeeded`、`failed`、`phone_verification_required`、`cancelled`。`phone_verification_required` 表示该账号当前任务因需要手机号验证而结束，不表示验证被绕过；不会触发 HeroSMS、其他接码服务或自动重试。任务历史和日志只保留脱敏原因。

账号绑定以 Sub2API 内部 `account_id` 为外键；队列运行前和回写前均验证平台/类型、资料版本及账号身份。新 OAuth 凭据的外部 OpenAI account ID 和 email 必须与原账号匹配。凭据条件写回须检查任务启动时的凭据指纹/版本，阻止过期任务覆盖手工更新或并行 refresh 得到的新凭据；写回范围仅含 OAuth 认证字段和必要的认证错误/调度状态。

### 账号删除生命周期

现状审计：账号 schema 使用 `SoftDeleteMixin`，Ent 的普通 Delete 会更新 `accounts.deleted_at`，不是物理删除。账号仓库还会删除 `account_groups` 和 `scheduled_test_plans`。`usage_logs.account_id` 虽定义了物理删除时 `ON DELETE CASCADE`，但软删除不会触发外键级联；本功能按用户要求，在账号软删除后显式清理该账号所有 `usage_logs`。

新增功能按以下顺序处理删除，且账号状态、重新授权资料及任务记录放入同一数据库事务：

1. 在一个事务中将账号标记为已删除，立即将 `accounts.credentials` 中的 OAuth/token 秘密擦除为兼容 schema 的空值，并物理删除该账号的 `account_reauth_profiles` 行和全部 `account_reauth_jobs` 行。先收集运行中任务 ID 并撤销租约；提交后清除该账号的 token cache 并尽力通知 worker 停止。软删除后即使恢复账号，也需重新导入 OAuth 凭据并绑定资料。
2. 迟到的 worker 结果必须经过账号 `deleted_at IS NULL`、profile 存在且启用、profile generation/version 一致、任务行和有效租约仍存在等检查。删除后这些条件均不成立，结果直接丢弃，不落库、不生成 profile，也不改变删除状态。取消信号用于尽早释放 worker 资源，数据库条件写回才是最终栅栏。
3. 活跃账号的已结束任务只留脱敏状态/原因，保留期最多 30 天，每账号最多保留最近 100 条；周期清理超期和超额记录。运行任务受活动任务唯一约束，每账号最多一个。
4. Worker 不在磁盘生成凭据、验证码或 OAuth token 文件；临时数据仅在内存或容器 tmpfs 中处理，任务结束或取消即清理。数据库不复制额外的邮箱凭据明文表或文件。
5. 清理该账号从最早到最新的全部 `usage_logs`，不受常规保留天数限制。删除动作触发立即首批清理；后台以 `deleted_at IS NOT NULL AND EXISTS(usage_logs)` 找到中断后仍有日志的 tombstone，续跑剩余批次，无需另建长期清理任务表。按现有 usage-log 清理器的有界批次执行，并复用其 group usage rollup 失效/同步路径；按 `account_id` 过滤，确保其他账号日志不受影响。账号删除后，该账号的本地用量明细消失，依赖这些日志的用户/API Key/分组统计也相应扣除并刷新。清理应幂等且可在进程重启后续跑，避免把大量历史日志塞进单个长事务。

账号删除策略已采纳：软删除时立即擦除 OAuth 凭据、清 token cache、删除重授权资料和任务，并清理该账号的全部 `usage_logs`；数据库只暂留不含认证秘密的最小 tombstone。建议 tombstone 默认保留 30 天，再由每日运行的后台任务按有界批次物理删除；保留期应可配置，任务需幂等、可续跑，并在删除前确认关联记录已清理。若存在 `ON DELETE RESTRICT` 引用，先处理引用；Spark 父/影子账号按子账号优先的顺序清除。账号在凭据擦除后不支持靠恢复软删除记录恢复登录，必须重新导入 OAuth 凭据。Sub2API 当前没有发现针对软删除账号/凭据的定期清理任务，需新增 tombstone 清理任务。PostgreSQL 删除行后空间通常由 autovacuum 回收并供数据库复用，数据文件大小未必立刻缩小；不为单个账号执行 `VACUUM FULL`。删除前生成的数据库备份仍可能包含当时的加密 profile 或 usage_logs，直到对应备份过期清理；单个账号删除时保留其他账号仍需使用的共享密钥环。

现有 usage-log 保留设置与账号删除清理是两件事：原始日志默认保留 90 天，聚合服务约每 6 小时执行保留清理，且可被运行时设置覆盖；`usage_cleanup.max_range_days=31` 是管理员手动清理任务单次允许的最大日期跨度，不是 31 天自动删除策略。重新授权终态任务另按 30 天/每账号 100 条上限保留；账号删除会直接删掉该账号的全部 job 行。

账号删除服务会级联删除 Spark 影子账号，因此每个实际删除的账号都需执行同一套 profile/job 物理清理、worker 取消及 fencing 规则。失败时事务回滚，避免账号已删除但秘密/活动任务仍被当成有效绑定的半完成状态。

### 容器密钥注入评审

**实现方案：宿主机 root-only 密钥环文件 + Compose file secret 只读挂载 + 容器 tmpfs 暂存。** 生产镜像入口先以 root 修复 `/app/data` 权限，再通过 `su-exec` 降到 UID 1000 的 `sub2api`；因此直接将宿主机 `root:root 0400` 文件挂载后交给应用读取会因 UID 不匹配而失败。当前入口脚本会在降权前将 Compose secret 暂存到 1 MiB tmpfs，并将文件设为 `sub2api:sub2api 0400`。主 Compose 与 standalone Compose 均有对应的 `docker-compose.reauth.yml` overlay。启用前仍需在宿主机创建真实 keyring 并验证目标 Compose 环境：

1. 在宿主机 `/etc/sub2api/reauth/keyring.json` 保存密钥环；目录 `0700`、文件 `0400`、属主 `root:root`。路径位于 Git checkout、`/opt/sub2api` 数据目录和 `.env` 之外。
2. 在生产 Compose 配置（含 standalone 部署文件）中用顶层 `secrets.file` 将该文件只读挂入 `sub2api` 容器的 `/run/secrets/reauth-keyring.json`；PostgreSQL、Redis 和 worker 都不挂载此密钥环。
3. Compose overlay 为 `/run/sub2api-secrets` 配置 tmpfs，并以 `OPENAI_REAUTH_KEYRING_FILE=/run/sub2api-secrets/keyring.json` 启动应用。入口脚本在降权前读取 `/run/secrets/reauth-keyring.json`，复制到 tmpfs 并设置属主 `sub2api:sub2api` 与权限 `0400`。环境变量只传文件路径，不传密钥内容；密钥不得出现在进程参数、容器环境值、日志或启动输出中。容器重建后从只读挂载重新暂存，tmpfs 中的副本随容器停止消失。
4. 使用带 `active_key_id` 和 `keys` 映射的 JSON 密钥环，例如 `{"active_key_id":"key-2026-09","keys":{"key-2026-09":"<64位hex>"}}`。新资料只用 active key 加密；旧 key 保留为只读解密键，直到所有对应密文完成重加密并校验后才退役。

Docker Compose 的本地 `file` secret 是只读文件挂载，不是 Swarm secret 的加密存储；静态密钥在宿主机上仍以文件形式存在。该方案的边界是：数据库单独泄露时密文仍受保护；宿主机 root、Docker daemon 管理权限或同时拿到数据库与密钥环的备份时，密文可被解开。密钥环备份应加密并与数据库备份分开保管。密钥缺失/损坏时只关闭自动重新授权并报告可诊断状态，Sub2API 主服务及既有账号 OAuth 凭据继续可用，绝不生成随机替代 key。

### 资料字段范围评审

profile 采用版本化 JSON 明文结构后整体 AES-GCM 加密；数据库明文仅保留内部 `account_id`、启停状态、密钥 ID、资料版本和时间戳。登录邮箱从现有账号凭据读取，不重复保存；密文只保留自动登录必需的密码和 TOTP 种子。API 仅回显绑定状态和脱敏标识。

| Payload 字段 | 保存规则 |
| --- | --- |
| `schema_version`、登录流程 `login_flow` | 必需；首版固定为 `password_totp`，拒绝未知流程值，不接收任意脚本或可执行配置 |
| OpenAI 登录密码 | 自动登录必需；整体加密保存，不写入日志、命令行或环境变量 |
| OpenAI TOTP seed | 仅支持账号已启用 authenticator TOTP 时保存；绝不保存预生成的一次性验证码 |

以下内容**不进入 profile payload**：Sub2API 账号已有的 OpenAI/Codex `access_token`、`refresh_token`（它们只存于账号凭据；worker 的新 token 作为单次任务结果返回并由 Sub2API 校验写回）；验证码、浏览器 cookie、登录 session、worker 临时文件或原始响应；可由账号行取得的 proxy 配置、共享 OAuth client secret、通用服务 URL；注册资料和与重授权无关的邮箱字段。解密后的资料及新 token 通过私有 IPC/管道短暂传递，禁止放进 worker 命令行参数或环境变量。worker 所需网络代理引用账号现有代理配置或服务级受控配置，不重复复制含密码的代理 URL 到 profile。

手机号、短信验证码、HeroSMS 或其他付费接码服务的密钥/配置均不属于字段模型。worker 一旦报告 `phone_verification_required`，任务直接进入终态；不会新增手机号资料字段或短信 provider adapter。

### 建议密钥管理

1. 复用 AES-256-GCM 算法，但使用单独的重新授权数据密钥；与 JWT、TOTP、数据库密码分开。按“容器密钥注入评审”用宿主机 root-only 密钥环文件和只读 Compose secret 注入，不写入数据库、账号表、普通设置、Git、`.env` 或日志；同一服务的所有实例使用同一稳定密钥环。
2. 密文使用带格式版本和 `key_id` 的 envelope。将用途、表和 `account_id` 作为 AEAD associated data，防止密文被移到另一个账号记录后仍可解密。当前 `AESEncryptor` 编码格式没有 key ID/AAD，需在后续实现时增加版本化封装。
3. 轮换采用“新 key 写入、旧 key 只读、分批解密重加密、校验完成后退役旧 key”；数据库备份与密钥备份分开保管。不能覆盖旧 key 后假设历史密文仍可读。
4. 缺少密钥或 `key_id` 无法解析时，重新授权功能保持关闭并保留密文；Sub2API 主服务继续运行，不清空资料、不回退明文。恢复密钥后再恢复处理。密钥丢失意味着需重新绑定资料，但不影响已有账号 OAuth 凭据或使用记录。

### 管理接口与验收

- 管理接口对秘密字段只写不读；列表只返回“已绑定/未绑定”、资料来源类型和脱敏账号标识。修改时管理员提交新资料以完整替换，不回显旧密码、TOTP、邮箱访问 token 或 OAuth token。
- 阶段 2 的评审用例：密钥只通过 root-only 宿主机文件与只读 Compose secret 注入，应用从 tmpfs 文件读取；容器重建/重启后同一密钥环仍可解密；密钥缺失或损坏时仅重授权功能 fail-closed；错 key、篡改密文和跨账号搬移均解密失败；轮换前后资料可读；重复绑定和并发创建受唯一约束；字段最小化、API/日志脱敏；手机号验证终态不生成接码调用；旧账号默认关闭。
- 上述为阶段 2 的原始评审验收清单；当前各阶段的实现状态以第 9 节为准。所有阶段继续排除 HeroSMS。

## 3. 功能需求

1. 全局功能默认关闭；管理员可启停，并设置扫描周期，默认 5 分钟。
2. 每个账号可单独启用/停用自动重新授权。只处理 OpenAI/Codex OAuth 类型，且账号与重新授权资料有明确、唯一的绑定。
3. 调度器读取持久化账号状态和可归因的上游认证错误，不为每个账号每 5 分钟主动制造一次上游请求。
4. 只有确认属于账号 OAuth 失效的 401 才创建重新授权任务。HTTP 403、429、5xx、网络超时、解析错误、调用方 API Key 401 均不触发。
5. 同一账号同一时刻最多有一个任务；失败后应用冷却和有上限的退避，不可每轮无限登录。
6. 重新授权成功后验证新凭据，再原子地更新 OAuth 凭据并清理该账号对应的认证错误状态。
7. 凭据更新不得重置或改写账号用量窗口、请求/Token 累计、使用记录、分组、优先级、代理、倍率、并发限制及其他非认证字段。
8. 管理页可查看功能开关、账号绑定、最近检查时间、当前状态、最近任务结果和失败原因；永远不展示密码、TOTP 种子、邮箱取件密钥或 token 原文。HeroSMS 不属于本功能。

## 4. 建议架构

```text
Sub2API scheduler (默认每 5 分钟)
  -> 401 分类器 / 候选选择器
  -> 持久化、幂等的 reauth job 队列
       -> ReauthProvider 接口
       -> 私有 Codex OAuth reauth worker（密码 + TOTP；移除所有 SMS/接码模块）
            -> toSub2 curl_cffi/TLS 协议登录会话
            -> 复用同一 Session 完成 OAuth 回调和 token exchange
  -> 新 OAuth 凭据验证
  -> 仅更新目标账号的认证字段
```

### 4.1 状态分类与候选选择

- 使用账号数据库中的状态、结构化失败原因和已有上游错误记录，建立明确的 `reauth_required` 判定；不要只用任意日志文本包含 `401` 来触发。
- 用稳定的 Sub2API `account_id` 绑定登录资料。邮箱只作展示/辅助校验，不作为唯一关联键，避免重复邮箱、大小写差异或账号更名造成串号。
- 账号被管理员删除、停用、解绑、关闭自动重授权或切换平台后，取消尚未执行的任务。账号删除时同步清除加密登录资料和任务；运行中任务用取消信号尽早停止，并通过账号未删除、资料版本和有效租约检查拒绝迟到结果。账号删除触发按 account_id 分批清理全部 usage_logs，并刷新相关聚合统计。
- 每次扫描只查询候选记录，加入分页/批次上限；默认重授权并发为 1，最多允许 2 个协议/TLS 登录会话，避免小内存主机被并发 helper 拖垮。
- 手机号验证只终止当前账号的 job：立即写入 `phone_verification_required`，释放 worker slot，不等待人工、不保留 running lease、不取消队列中的其他账号任务。并发为 1 时，该 worker 随即领取下一个账号任务；并发为 2 时，另一个 worker 也不受影响。

### 4.2 重新授权 Provider

定义与具体 OAuth 实现解耦的 `ReauthProvider` 接口。当前实现由 Sub2API 进程内 worker 调用 provider；每个任务按需创建一个短生命周期的 toSub2-compatible `curl_cffi` Session，通过官方 JSON 协议完成 ChatGPT CSRF/signin、密码 + TOTP、workspace 选择和 Codex OAuth。登录资料只提交到官方密码验证接口，从本地 OAuth callback 提取 code/state，再复用现有 OAuth code exchange。登录资料解密后只在任务内存和 helper Session 中使用；任务状态、审计与日志不包含资料或 token 原文。

OAuth code exchange/refresh 也可以通过可选的 toSub2-compatible transport 发送：
`curl_cffi` 负责 Chrome TLS impersonation，Python Session 负责代理和 CookieJar。
Cloudflare solver 只在响应中明确存在 challenge 标记时运行；每个请求最多求解一次，
求解成功后使用同一 Session 重放原始请求。普通
`auth.openai.com/log-in` HTML 页面会报告为协议/登录状态错误，不会误判为 Cloudflare
检查；挑战仍存在时返回 `security_challenge_required`。普通 JSON 400/409、
403 非 challenge、网络错误和 solver 失败不会被误判成已解决。helper 的响应帧、
请求体、challenge HTML 和错误预览均有大小上限。

阶段 1 的 `codex-auto-sms-receiver` 仅作接口与边界参考，不被运行时调用或作为子进程启动；不引入注册或 HeroSMS 接码集成。参考项目遇到重复手机号验证时跳过该账号当前任务，随后由人工或 HeroSMS 完成验证；这不是绕过手机号验证。Sub2API 协议登录检测到手机号验证后立刻结束当前账号 job 并继续其他队列任务；邮箱验证码或其他安全挑战转为 `needs_input`。代理来自目标账号绑定的 Sub2API 代理，并由 curl_cffi Session 保持同一出口和 Cookie 状态。

### 4.3 登录资料和凭据安全

- 重新授权资料单独建模；使用 2.3 设计的独立稳定密钥与版本化 AES-GCM envelope 加密静态存储。
- 支持按 `account_id` 增删、轮换和解绑。密码与 TOTP 种子均按秘密字段处理；不包含邮箱取件凭据或 HeroSMS/SMS 接码密钥。
- 所有日志、任务事件、API 响应、审计记录和错误上报都必须脱敏；不能记录验证码、Authorization Header、access/refresh token 或完整登录资料。
- 管理接口采用现有管理员鉴权和权限校验；列表 DTO 默认只返回“已绑定/未绑定”和掩码信息。

### 4.4 原子更新与数据保留

- 复用现有 OAuth 凭据应用逻辑，或抽取事务化服务；不要整行覆盖账号 JSON/Ent 记录。
- 在事务中校验账号 ID、平台、OAuth 类型和任务版本；只更新认证字段及必要的 auth 状态/时间戳。
- 使用条件更新或凭据版本号，避免较早任务的结果覆盖之后人工更新的 token。
- 成功后使旧 token 缓存失效，并重新启用符合原状态的调度；不修改任何用量窗口/本地累计字段。
- 新 token 无效、邮箱不匹配或任务过期时拒绝写入，保留原凭据并记录脱敏失败原因。

## 5. 持久化状态建议

实际表结构按项目 Ent schema 与 migration 约定设计，建议至少有：

- `account_reauth_profile`：`account_id` 唯一外键、启用标记、加密后的登录资料、凭据版本、创建/更新时间。
- `account_reauth_job`：任务 ID、`account_id`、触发原因、状态、尝试次数、下次可运行时间、开始/结束时间、脱敏结果码。
- 账号状态字段或现有错误状态中可查询的 `reauth_required` 归因，避免重复解析原始日志。

任务状态采用 2.3 中定义的状态集。用数据库唯一约束/租约确保跨实例也不会重复领取同一账号任务。migration 需支持空资料部署，旧账号默认不启用。

## 6. 管理端交互

- 系统设置：总开关、扫描间隔（默认 5 分钟）、最大并发、重试上限和冷却时间。
- 账号编辑页：独立的自动重新授权开关、登录资料绑定状态和“测试登录资料”动作。
- 账号列表：认证状态、最近检测时间、最近任务结果；不把用量统计和授权任务状态混成同一指标。
- 操作：立即扫描、取消待执行任务、解绑/删除重新授权资料；高敏感资料变更要求二次确认。

## 7. 失败与限流策略

- 对每账号设置冷却；建议初始冷却不少于 10 分钟，重试次数有上限，并采用指数退避和随机抖动。
- 登录需要用户输入验证码或额外确认时，任务转为 `needs_input` 并显示明确状态，不反复提交登录。
- 如重新授权流程要求手机号验证或 SMS 验证码，任务以 `phone_verification_required` 终态结束；不启用 HeroSMS/其他付费接码渠道，不重试该任务。
- HeroSMS 及其他付费手机号接码实现不属于本功能范围；不新增其代码、配置、依赖或 UI。
- worker/TOTP 不可用、代理失败、授权服务器暂时错误等均记录为可区分的任务失败，不改变账号原有用量数据。
- 每轮扫描设总时限、候选上限和并发上限；扫描失败只影响该轮，不阻塞网关请求处理。
- 关闭全局功能后，不再新建任务；运行中的任务可安全收尾或由管理员取消。

## 8. 测试与验收标准

### 后端

- 只有目标账号的结构化 OAuth 401 能进入队列；调用方密钥 401、403、429、5xx 和网络错误均不触发。
- 连续扫描不会创建重复任务；多个应用实例不会同时处理同一账号。
- 成功更新只变更 OAuth 认证相关字段；用量窗口、累计统计、使用记录、分组和调度配置前后不变。
- 旧任务不能覆盖人工更换的新凭据；失败任务不会清空现存凭据。
- 所有秘密在日志和 API DTO 中均脱敏；默认关闭功能的旧账号行为不变。
- migration、单元测试、集成测试覆盖首次安装、升级和回滚场景。
- 删除账号时 OAuth 凭据立即擦除、token cache 失效、profile 与该账号全部 job 行在同一事务中清理；运行中 worker 尽力取消且迟到结果被 fencing 拒绝；该账号全部 usage_logs 经有界、可续跑的清理后消失，相关统计同步刷新；最小 tombstone 默认保留 30 天后由每日有界清理任务物理删除，且不会留下阻止清理的引用。

### 端到端

1. 创建一个专用测试账号并显式绑定重新授权资料。
2. 注入可控的 401 状态，确认 5 分钟扫描周期内只生成一个任务。
3. 通过私有 worker 的密码 + TOTP OAuth 流程完成重新授权，确认新凭据写回同一 `account_id`；不涉及 SMS 或接码。
4. 验证账号恢复可调度，同时用量与历史记录逐字段保持不变。
5. 注入验证码超时、登录被拒、无关 401、重复回调和并发任务，确认均按预期处理。

### 验收门槛

- 全局默认关闭，管理员开启后周期默认 5 分钟。
- 401 只触发对应账号的一次排队任务，不触发注册或批量账号操作。
- 成功重授权后该账号可恢复调用；失败时原凭据和账号用量数据保留。
- 不在日志、错误响应、导出和普通账号列表中泄漏秘密。
- 后端单元/集成测试、前端类型检查和构建通过。

## 9. 阶段任务表

按阶段顺序推进。每阶段验收通过后再开始下一阶段，并更新本表状态。

| 阶段 | 任务 | 交付物与验收条件 | 状态 |
| --- | --- | --- | --- |
| 0. 现状审计 | 固定 v0.2.8 基线；追踪账号 401 状态从上游响应到数据库/日志的记录路径；梳理现有 OAuth 刷新、凭据写回、token cache 和调度器。 | 形成代码路径与状态分类表；能区分普通 token 过期、OAuth 会话撤销、调用方密钥错误、403/429 和网络故障。 | 已完成；详见 2.1 |
| 1. SMS 项目接口审计 | 检查 `codex-auto-sms-receiver` 的许可证、登录/OAuth 流程、验证码来源、后台运行能力，以及是否有稳定 API/CLI/任务接口。 | 明确 Sub2API 与它的调用契约。若没有机器接口，先决定新增本机 worker/API；不把文件导出或 UI 自动点击当成集成接口。 | 已完成；决定由 Sub2API 管理并调用私有 worker，详见 2.2 |
| 2. 数据模型与密钥方案 | 固定 worker 最小输入/输出契约，设计 `account_id` 绑定、profile/job 表、外部密钥环和脱敏 DTO。 | migration、AES-GCM profile repository、版本化 `schema_version/login_flow`、管理员 profile/status DTO 已实现；默认关闭；登录资料不进明文列或审计日志。软删除 migration 会擦除账号凭据并清理该账号 usage logs、profile/job；主/standalone Compose 均提供 file-secret + tmpfs overlay。仍需目标 PostgreSQL/Compose 运行验收。 | 代码与静态检查已补齐；运行时集成验证待做 |
| 3. 401 分类与周期调度 | 复用现有默认 5 分钟 refresh 扫描；持久化 OpenAI OAuth 401 即使 expiry 尚远也进入标准 refresh-token 流程。 | 已覆盖目标 OpenAI OAuth、active、refresh token 和 `OAuth 401:` 原因；非 OAuth/API Key、其他平台/错误原因及永久错误均不触发。不可恢复后的 reauth 任务由阶段 4 接管。 | 已完成（2026-09-23） |
| 4. 持久化任务队列 | PostgreSQL 幂等队列、租约、跨实例领取、有限重试、周期候选扫描和终态清理。 | 每账号最多一个活动任务；`SKIP LOCKED` 领取；worker ID 带随机实例标识防旧租约写回；默认并发 1、硬上限 2；手机号验证只结束当前 job 并继续队列；自动扫描对同一 profile/凭据版本幂等，管理员手动排队可在人工处理后重试终态任务。已补 PostgreSQL 集成用例，覆盖幂等入队、双 worker 竞争、租约恢复、手机号验证终态、手动重试和终态清理。 | 核心代码、单测和集成用例已补齐；待 Docker/PostgreSQL 实际运行验收 |
| 5. 重新授权 Provider | 正常密码 + TOTP OAuth；toSub2 `curl_cffi` 协议会话完成官方 CSRF/signin、密码、TOTP、workspace、session/select 和本地 callback，遇到手机号验证停止；OAuth exchange/refresh 可选同一 TLS transport。 | 成功通过现有 OAuth exchange 取回新 token；state 校验；账号代理；协议会话保持 Cookie/TLS 状态；challenge 仅在真实响应中出现时处理；验证码/安全挑战可分类；不含 SMS/接码代码。 | 协议 Provider 与 transport bridge 已实现；需安装 helper 依赖并做专用账号端到端测试 |
| 6. 凭据验证与原子写回 | 校验新 token 的 email/account ID，按原 credentials 条件事务写回并同步调度缓存。 | 失败不覆盖旧凭据；旧任务不能覆盖新凭据；成功只变认证字段，不更新用量、分组、代理或并发。 | 核心代码已完成；需 PostgreSQL 集成测试逐字段验收 |
| 7. 管理界面与权限 | 提供管理员 profile 保存/解绑、状态/历史查询及手动入队 API 与前端交互。 | API 复用管理员路由鉴权；请求体不记审计日志；响应不回显密码/TOTP/token；账号页支持绑定/更新/删除资料、启停、手动排队、查看任务及手机号验证状态。 | 后端 API 与前端管理 UI 已实现；定向测试、类型检查、lint 和生产构建通过 |
| 8. 验证、灰度与部署 | 完成全量测试、安全审查、容器密钥挂载、helper 运行时依赖和小流量验证。 | 本地编译构建后再上传，生产服务器不编译；服务器版本备份只留一份；完成上传后再清理本地构建缓存；验证 helper 帧/响应上限、Cookie session 重放、solver 超时和默认关闭行为。 | 进行中：transport 单测与 Compose 配置已补齐；尚需本地 Go/前端全量检查、Python/Node helper 依赖检查、PostgreSQL/容器运行时集成与专用 OAuth 端到端验证 |

## 10. 交付与回滚

- 新配置默认关闭；数据库迁移不要求旧账号补填登录资料。
- 保留现有普通 OAuth refresh 逻辑；自动重新授权是独立能力，可通过全局开关立即停用。
- 回滚代码时不得删除账号用量、历史使用记录或既有 OAuth 凭据；迁移回滚遵循项目数据库迁移流程。
- 发布前记录 commit、镜像 tag、迁移版本和验证结果；部署备份按仓库/运维约定只保留一份。

## 11. 剩余工作与限制

- 全局默认关闭。启用前需在宿主机生成稳定的外置 AES-256 keyring，将 `OPENAI_REAUTH_KEYRING_HOST_FILE` 设为其绝对路径，在 `.env` 中显式设 `OPENAI_REAUTH_ENABLED=true`，并用基础 Compose 文件加 `docker-compose.reauth.yml` overlay 启动；standalone 使用 `docker-compose.standalone.yml` 作基础文件。不要把真实密钥环提交到 Git 或 `.env`。
- 默认一个协议/TLS helper worker；小内存服务器不要提高并发。配置允许最多 2 个同时登录任务；手机号验证会立即结束当前任务并释放 slot，另一个 worker 和后续队列不受影响。
- toSub2-compatible transport 默认关闭；启用前需使用 `deploy/Dockerfile` 的
  `INCLUDE_TOSUB2_RUNTIME=true` 构建自定义镜像，或在同一运行容器提供 Python
  `curl_cffi==0.15.0`、Node.js 20+ 和 `jsdom==26.1.0`，并设置
  `OPENAI_OAUTH_TOSUB2_*` 环境变量。该 helper 每次 OAuth 请求短生命周期运行，
  最多求解一次 challenge 并重放一次，未配置依赖时不会自动改走服务器直连。
- 后端管理员 API 与账号页资料管理界面已实现；前端支持安全绑定/更新/删除资料、启停、手动入队及查看最近任务状态。前端定向测试、类型检查、lint 和生产构建已通过。
- Compose file-secret/tmpfs 配置、入口降权前暂存逻辑及主/standalone Compose 静态配置校验已完成；新增 migration `242_purge_deleted_account_auth_and_usage.sql`，并显式重建软删除 trigger，软删除时擦除 `accounts.credentials`、删除该账号 `usage_logs`、profile 和 job；单账号与批量管理员删除入口都会清理 OAuth token cache。尚未在 Docker 容器内验证实际 secret 文件权限、容器重启后的解密行为，也未运行 PostgreSQL migration/并发集成用例；这些用例已加入 `backend/internal/repository/openai_reauth_repo_integration_test.go`，需在有 Docker 的本地环境执行。
- 账号删除策略已确认：删除 profile/job，并依项目既定逻辑清理 OAuth 凭据、token cache 和使用记录；生产删除流程还需按 2.3 的清理要求做数据库集成验证。
