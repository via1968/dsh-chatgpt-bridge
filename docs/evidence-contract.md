# Evidence contract

每个任务至少产生以下证据类型：

| 类型 | 产生时机 | 作用 |
| --- | --- | --- |
| `workspace.before` | DSH 启动前 | 记录 git 分支、状态、已暂存/未暂存 diff 和未跟踪文件摘要 |
| `dsh.session_update` | DSH ACP 运行中 | 记录提交的 assistant、thought、工具生命周期等语义更新 |
| `dsh.prompt_result` | DSH 提示词结算后 | 记录 stop reason 和 assistant 输出摘要 |
| `workspace.after` | DSH 提示词结算后 | 与执行前快照比较，确认实际工作区变化 |
| `workspace.delta` | DSH 提示词结算后 | 记录执行前后 HEAD、受限 pathspec，以及执行期间提交的总 diff |
| `task.event_log` | 每轮结束 | 给出桥接状态变化和事件序号索引 |
| `acceptance.record` | ChatGPT 记录验收时 | 将每条验收条件绑定到本任务证据 ID |

`accepted` 只表示桥接器验证了如下条件：

1. 计划版本仍是被批准的版本；
2. 每条验收条件都恰好出现一次；
3. 每条条件的结果都是 `pass`；
4. 引用的证据存在、属于同一个计划哈希和当前执行轮次；`pass` 条件至少引用一条证据，且满足该条件声明的 `evidenceKinds`（如有）。

工作区证据中的 `sha256` 是原始本地内容的哈希，`contentSha256`（存在时）是对外返回的脱敏内容哈希；敏感文件不会返回正文。Git 状态和 diff 使用计划允许目录生成 pathspec，不包含同仓库其他目录的变更。

它不替代硬件、账号、网页或外部系统验证。大小受配置项限制；超过限制的字段会带 `[truncated]` 标记，不能按完整原文使用。
