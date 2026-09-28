import { McpServer } from '@modelcontextprotocol/sdk/server/mcp.js'
import * as z from 'zod/v4'

function jsonResult(value, isError = false) {
  const payload = JSON.stringify(value, null, 2)
  return {
    ...(isError ? { isError: true } : {}),
    content: [{ type: 'text', text: payload }],
    structuredContent: value,
  }
}

function register(server, name, config, handler) {
  server.registerTool(name, config, async args => {
    try {
      return jsonResult(await handler(args))
    } catch (error) {
      return jsonResult({ error: String(error?.message ?? error), code: error?.code ?? 'BRIDGE_ERROR' }, true)
    }
  })
}

const scopeSchema = z.object({
  workspace: z.string().min(1),
  allowedPaths: z.array(z.string().min(1)).min(1),
  operations: z.array(z.enum(['read', 'write', 'execute'])).min(1),
})

const acceptanceCriteriaSchema = z.array(z.object({
  id: z.string().min(1),
  description: z.string().min(1),
  evidenceKinds: z.array(z.string().min(1)).optional(),
})).min(1)

export function createMcpServer(core, auth, kind) {
  const server = new McpServer({ name: `dsh-chatgpt-bridge-${kind}`, version: '0.1.0' })
  const hint = description => ({
    description,
    _meta: auth.securityMeta(kind),
    ...(kind === 'inspect' ? { annotations: { readOnlyHint: true, destructiveHint: false, idempotentHint: true } } : {}),
  })

  if (kind === 'inspect') {
    register(server, 'bridge_inspect_plan', {
      ...hint('Read an immutable plan version, its hash, scope, approval state, and acceptance criteria.'),
      inputSchema: { planId: z.string().min(1), version: z.number().int().positive().optional() },
    }, args => core.getPlan(args.planId, args.version))

    register(server, 'bridge_inspect_task', {
      ...hint('Read task status, DSH semantic events, approval/permission state, and evidence identifiers. A finished task is not automatically accepted.'),
      inputSchema: { taskId: z.string().min(1) },
    }, args => core.getTask(args.taskId))

    register(server, 'bridge_inspect_evidence', {
      ...hint('Read one persisted evidence record by identifier, including its content hash and capture data.'),
      inputSchema: { evidenceId: z.string().min(1) },
    }, args => core.getEvidence(args.evidenceId))

    register(server, 'bridge_inspect_approval', {
      ...hint('Read the status of a human approval request. Approval is completed through the separate authenticated human channel.'),
      inputSchema: { approvalId: z.string().min(1) },
    }, args => core.getApproval(args.approvalId))

    register(server, 'bridge_inspect_workspace', {
      ...hint('Capture read-only git/workspace facts. This tool does not modify files or execute project commands.'),
      inputSchema: { workspace: z.string().min(1) },
    }, args => core.inspectWorkspace(args.workspace))

    register(server, 'bridge_inspect_dsh', {
      ...hint('Inspect the DSH ACP adapter and, optionally, its persisted session list.'),
      inputSchema: { includeSessions: z.boolean().optional(), cwd: z.string().optional() },
    }, args => core.inspectDsh(args))

    return server
  }

  register(server, 'bridge_submit_plan', {
    ...hint('Submit a new immutable plan version. It never starts DSH and never mutates an earlier version.'),
    inputSchema: {
      planId: z.string().min(1).optional(),
      version: z.number().int().positive().optional(),
      objective: z.string().min(1),
      scope: scopeSchema,
      constraints: z.array(z.string()).optional(),
      acceptanceCriteria: acceptanceCriteriaSchema,
      executionPrompt: z.string().min(1),
    },
  }, args => core.submitPlan(args))

  register(server, 'bridge_request_plan_approval', {
    ...hint('Create an approval request for a specific plan hash/version. The model cannot approve it through this tool.'),
    inputSchema: { planId: z.string().min(1), version: z.number().int().positive().optional(), reason: z.string().optional() },
  }, args => core.requestPlanApproval(args))

  register(server, 'bridge_start_task', {
    ...hint('Start one DSH task only after the exact plan version has been approved through the separate human channel.'),
    inputSchema: { planId: z.string().min(1), version: z.number().int().positive().optional(), taskId: z.string().min(1).optional() },
  }, args => core.startTask(args))

  register(server, 'bridge_pause_task', {
    ...hint('Pause the current DSH prompt and suppress automatic continuation until resume_task is explicitly called.'),
    inputSchema: { taskId: z.string().min(1) },
  }, args => core.pauseTask(args.taskId))

  register(server, 'bridge_resume_task', {
    ...hint('Resume a paused or needs_reconcile task on the same approved plan and current workspace state.'),
    inputSchema: { taskId: z.string().min(1) },
  }, args => core.resumeTask(args.taskId))

  register(server, 'bridge_cancel_task', {
    ...hint('Cancel a queued or running task. The bridge records cancellation separately from acceptance.'),
    inputSchema: { taskId: z.string().min(1) },
  }, args => core.cancelTask(args.taskId))

  register(server, 'bridge_send_correction', {
    ...hint('Send an in-scope correction after review. Changing scope, constraints, or acceptance criteria requires a new plan version.'),
    inputSchema: { taskId: z.string().min(1), correction: z.string().min(1) },
  }, args => core.sendCorrection(args))

  register(server, 'bridge_record_acceptance', {
    ...hint('Record criterion-by-criterion acceptance with evidence identifiers. Only all-pass criteria move a task to accepted.'),
    inputSchema: {
      taskId: z.string().min(1),
      summary: z.string().optional(),
      criteria: z.array(z.object({
        id: z.string().min(1),
        result: z.enum(['pass', 'fail', 'unverified']),
        evidenceIds: z.array(z.string()).optional(),
        note: z.string().optional(),
      })).min(1),
    },
  }, args => core.recordAcceptance(args))

  return server
}
