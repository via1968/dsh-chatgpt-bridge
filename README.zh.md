# ChatGPT 与 DSH 协作桥接器

这是按照《实现ChatGPT与DSH协作架构》落地的独立桥接服务。桥接器只负责鉴权、计划版本、审批状态、任务映射、DSH ACP 交接和证据索引；实际项目执行由本机 DSH 完成，不修改 DSH 核心代码。

当前已实现：

- `/mcp/inspect`：只读调查、计划/任务/审批/证据读取、工作区快照和 DSH 状态。
- `/mcp/control`：提交不可原地修改的计划版本、申请人工审批、启动/暂停/恢复/取消任务、提交同范围修正和记录验收。DSH 逐次权限不在 MCP 中放行。
- inspect 与 control 使用不同 bearer token；也可启用本地 OAuth 2.1 authorization-code + PKCE 流程。
- DSH 通过 `dsh --profile acp` 的 ACP stdio 接口长驻连接；桥接重启后不会自动把执行中的任务伪装成完成，而是标记为 `needs_reconcile`，需要先查看持久化证据，再显式恢复或取消。
- 任务状态区分 `running`、`waiting_permission`、`pausing`、`cancelling`、`collecting_evidence`、`paused`、`needs_reconcile`、`waiting_review`、`rework_required`、`accepted`、`failed` 和 `cancelled`；DSH prompt 结束后必须先完成本轮证据收集，才会进入 `waiting_review`。
- 执行前/后工作区快照、HEAD 间的提交变更、DSH ACP 语义事件、提示词结果和验收记录形成可读取的证据索引；输出会做常见凭据脱敏并设大小上限。
- 人工审批不是 MCP 工具：模型只能创建审批请求，真正放行使用独立的 `POST /v1/approvals/<approvalId>` 人工通道。
- DSH 权限请求同样不属于 MCP 工具，使用独立的 `POST /v1/permission-requests/<permissionId>` 人工通道；需要同时提供 `taskId`、`allow` 和可选 `optionId`。
- 当前 ACP 只支持以一个已存在目录作为 DSH 会话边界；多目录或文件级 `allowedPaths` 会在提交计划时失败关闭，不会仅依赖自然语言约束。

## 本地启动

要求 Node.js 22 或更高版本。先复制环境变量示例并设置三类不同口令：

```powershell
Copy-Item .env.example .env
$env:BRIDGE_INSPECT_TOKEN = '<long-random-inspect-token>'
$env:BRIDGE_CONTROL_TOKEN = '<long-random-control-token>'
$env:BRIDGE_HUMAN_APPROVAL_TOKEN = '<long-random-human-token>'
```

安装依赖并启动：

```powershell
npm install
npm start
```

默认仅监听 `127.0.0.1:8787`。项目工作区可通过 `BRIDGE_WORKSPACE_ROOT` 限制；建议设置为需要协作的仓库根目录。桥接器会读取 DSH 所需的本机环境变量，但不会把环境变量或凭据放入 MCP 返回值。

## 人工审批

ChatGPT 或 MCP Inspector 调用 `bridge_request_plan_approval` 后，使用返回的 `approval.id` 查看审批内容。用户在本机独立执行：

```powershell
$body = @{ decision = 'approve'; comment = '确认在当前范围执行' } | ConvertTo-Json
Invoke-RestMethod `
  -Method Post `
  -Uri 'http://127.0.0.1:8787/v1/approvals/<approvalId>' `
  -Headers @{ 'X-Bridge-Human-Token' = $env:BRIDGE_HUMAN_APPROVAL_TOKEN } `
  -ContentType 'application/json' `
  -Body $body
```

随后才允许调用 `bridge_start_task`。计划的范围、约束或验收条件变化必须重新提交更高版本并重新审批；同范围的实现修正可以使用 `bridge_send_correction`。

DSH 运行中的逐次权限请求会出现在 `bridge_inspect_task` 的 `pendingPermission` 中。人工确认示例：

```powershell
$body = @{ taskId = '<taskId>'; allow = $true; optionId = 'allow-once' } | ConvertTo-Json
Invoke-RestMethod `
  -Method Post `
  -Uri 'http://127.0.0.1:8787/v1/permission-requests/<permissionId>' `
  -Headers @{ 'X-Bridge-Human-Token' = $env:BRIDGE_HUMAN_APPROVAL_TOKEN } `
  -ContentType 'application/json' `
  -Body $body
```

`allow` 会再次校验当前批准的计划版本、ACP 工具类型、工具路径和会话绑定；未知工具形状、超时或越界请求失败关闭。

## MCP / ChatGPT 连接

本地验证可使用 MCP Inspector：

```powershell
npx @modelcontextprotocol/inspector@latest
```

连接 `http://127.0.0.1:8787/mcp/inspect` 或 `/mcp/control` 时使用对应 bearer token。对 ChatGPT 网页连接，需要把桥接器放在公网 HTTPS 或 Secure MCP Tunnel 后，并使用：

- `https://<public-host>/mcp/inspect`
- `https://<public-host>/mcp/control`

官方 MCP 鉴权要求资源元数据、OAuth discovery、`resource` 回传、PKCE `S256` 和每次请求的 issuer/audience/scope 校验。本项目提供了可用于开发验证的本地 OAuth 端点；正式公网部署前仍应使用受维护的身份提供商、TLS 反向代理或 Secure MCP Tunnel，并重新验证账号/工作区的开发者模式政策。不要把 loopback 地址直接声称为 ChatGPT 已可访问。

## 验收顺序

1. `npm run check` 和 `npm test`。
2. `GET /healthz`，确认桥接器运行且 DSH 尚未被误报为已连接。
3. 用 inspect token 调 `bridge_inspect_workspace`，确认只读快照。
4. 提交计划、申请审批，用独立人工通道批准。
5. 调 `bridge_start_task`，再轮询 `bridge_inspect_task` 和 `bridge_inspect_evidence`。
6. 对每条验收条件调用 `bridge_record_acceptance`；每条 `pass` 必须引用当前执行轮次的证据，只有全量 `pass` 且证据类型满足计划要求时才会进入 `accepted`。
7. 最后再用 HTTPS/Tunnel 连接 ChatGPT，记录实际选中的工具、参数、返回值、鉴权和确认行为。

## 与方案的边界

本实现已经把“稳定接口、计划校验、人工审批、DSH 适配、暂停/恢复语义和证据索引”落到代码中；它没有把“网页保持打开”当作自动监督，也没有声称 Plus 账号上的连续自动往返已经验证。网页长任务、定时回访、开发者模式和公网连接需要在当前账号/工作区上做单独的真实联调。
