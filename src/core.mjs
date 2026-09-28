import { randomUUID } from 'node:crypto'
import { EventEmitter } from 'node:events'
import { assertDirectory, assertPathListAllowed, captureWorkspaceDelta, captureWorkspaceSnapshot, isPathWithin, normalizeAbsolutePath } from './workspace.mjs'
import { clone, newId, sha256, stableStringify } from './persistence.mjs'

const OPERATIONS = new Set(['read', 'write', 'execute'])
const STOP_REASONS = new Set(['end_turn', 'max_tokens', 'refusal', 'cancelled', 'max_turn_requests'])
const ACTIVE_TASK_STATUSES = new Set(['queued', 'running', 'waiting_permission', 'pausing', 'cancelling', 'paused', 'needs_reconcile', 'waiting_review', 'rework_required'])
const RUNNABLE_TASK_STATUSES = new Set(['queued', 'running', 'rework_required', 'paused', 'needs_reconcile'])

function now() {
  return new Date().toISOString()
}

function text(value, label, { max = 20000, optional = false } = {}) {
  if (value === undefined && optional) return undefined
  if (typeof value !== 'string' || value.trim() === '') throw new Error(`${label} must be a non-empty string`)
  if (value.length > max) throw new Error(`${label} exceeds ${max} characters`)
  return value
}

function capText(value, max) {
  const input = String(value ?? '')
  if (Buffer.byteLength(input, 'utf8') <= max) return input
  let end = Math.min(input.length, max)
  while (end > 0 && Buffer.byteLength(input.slice(0, end), 'utf8') > max) end -= 1
  return `${input.slice(0, end)}\n[truncated]`
}

function redactText(value) {
  return String(value ?? '')
    .replace(/(Bearer\s+)[A-Za-z0-9._~+/=-]+/gi, '$1[REDACTED]')
    .replace(/(sk-[A-Za-z0-9_-]{12,})/g, '[REDACTED_API_KEY]')
    .replace(/((?:api[_-]?key|token|secret|password)\s*[=:]\s*)[^\s,;]+/gi, '$1[REDACTED]')
}

function redactValue(value, maxBytes) {
  if (typeof value === 'string') return capText(redactText(value), maxBytes)
  if (Array.isArray(value)) return value.map(item => redactValue(item, maxBytes))
  if (value !== null && typeof value === 'object') {
    const result = {}
    for (const [key, item] of Object.entries(value)) {
      result[key] = redactValue(item, maxBytes)
    }
    return result
  }
  return value
}

function operationForToolCall(toolCall = {}) {
  const kind = String(toolCall.kind ?? '').toLowerCase()
  if (['read', 'search', 'think', 'fetch'].includes(kind)) return 'read'
  if (['edit', 'delete', 'move'].includes(kind)) return 'write'
  if (kind === 'execute') return 'execute'
  const name = String(toolCall.name ?? toolCall.title ?? '').toLowerCase()
  if (/\b(read|search|list|glob|grep|find|cat|stat|inspect|fetch)\b/.test(name)) return 'read'
  if (/\b(edit|write|delete|move|mkdir|patch|apply[_-]?patch|rename|copy)\b/.test(name)) return 'write'
  if (/\b(bash|shell|command|exec|execute|terminal|powershell|python|node|run)\b/.test(name)) return 'execute'
  return 'unknown'
}

function errorWithCode(message, code) {
  const error = new Error(message)
  error.code = code
  return error
}

async function deriveExecutionCwd(workspace, allowedPaths) {
  if (allowedPaths.length !== 1) {
    throw errorWithCode(
      'DSH ACP can enforce only one existing directory as the session boundary; multiple allowedPaths are rejected',
      'SCOPE_NOT_ENFORCEABLE',
    )
  }
  const executionCwd = await assertDirectory(allowedPaths[0], 'scope.allowedPaths[0]')
  if (!isPathWithin(workspace, executionCwd)) {
    throw errorWithCode('scope.allowedPaths[0] is outside scope.workspace', 'SCOPE_NOT_ENFORCEABLE')
  }
  return executionCwd
}

async function resolveWorkspaceScope(value, configuredRoot) {
  const candidate = normalizeAbsolutePath(value, 'scope.workspace')
  const workspace = await assertDirectory(candidate, 'scope.workspace')
  if (configuredRoot !== undefined) {
    const root = await assertDirectory(configuredRoot, 'BRIDGE_WORKSPACE_ROOT')
    if (!isPathWithin(root, workspace)) throw errorWithCode(`scope.workspace is outside BRIDGE_WORKSPACE_ROOT: ${workspace}`, 'SCOPE_OUT_OF_BOUNDS')
  }
  return workspace
}

function pathValuesFromToolCall(toolCall = {}) {
  const rawInput = toolCall.rawInput
  if (rawInput === null || typeof rawInput !== 'object') return []
  const values = []
  const visit = value => {
    if (typeof value === 'string') {
      if (/[/\\]/.test(value) || /^[A-Za-z]:/.test(value)) values.push(value)
      return
    }
    if (Array.isArray(value)) {
      for (const item of value) visit(item)
      return
    }
    if (value !== null && typeof value === 'object') {
      for (const [key, item] of Object.entries(value)) {
        if (/^(file_?path|path|paths|directory|directories|cwd|workdir|workspace)$/i.test(key)) visit(item)
        else if (Array.isArray(item) || (item !== null && typeof item === 'object')) visit(item)
      }
    }
  }
  visit(rawInput)
  return values
}

function toolCallWithinScope(toolCall, allowedPaths, executionCwd) {
  const values = pathValuesFromToolCall(toolCall)
  for (const value of values) {
    if (!value.startsWith('/') && !/^[A-Za-z]:[\\/]/.test(value)) continue
    const normalized = value.replaceAll('\\', '/')
    if (!allowedPaths.some(path => isPathWithin(path, normalized))) {
      return { ok: false, value }
    }
    if (!isPathWithin(executionCwd, normalized)) return { ok: false, value }
  }
  return { ok: true }
}

function latestPlan(state, planId) {
  const plan = state.plans[planId]
  if (plan === undefined) throw new Error(`unknown plan: ${planId}`)
  return plan.versions[String(plan.latestVersion)]
}

function findPlanVersion(state, planId, version) {
  const plan = state.plans[planId]
  if (plan === undefined) throw new Error(`unknown plan: ${planId}`)
  const selectedVersion = version ?? plan.latestVersion
  const selected = plan.versions[String(selectedVersion)]
  if (selected === undefined) throw new Error(`unknown plan version: ${planId}@${selectedVersion}`)
  return selected
}

function taskBySession(state, sessionId) {
  return Object.values(state.tasks).find(task => task.dshSessionId === sessionId)
}

export class BridgeCore extends EventEmitter {
  constructor({ config, store, dsh }) {
    super()
    this.config = config
    this.store = store
    this.dsh = dsh
    this.dsh.on('update', update => { void this.onDshUpdate(update).catch(error => this.emit('internal-error', { stage: 'dsh.update', error: String(error.message ?? error) })) })
    this.dsh.on('permission-request', request => { void this.onPermissionRequest(request).catch(error => this.emit('internal-error', { stage: 'permission.request', error: String(error.message ?? error) })) })
    this.dsh.on('permission-timeout', request => { void this.onPermissionTerminal(request, 'timeout').catch(error => this.emit('internal-error', { stage: 'permission.timeout', error: String(error.message ?? error) })) })
    this.dsh.on('permission-decision', request => { void this.onPermissionTerminal(request, request.decision).catch(error => this.emit('internal-error', { stage: 'permission.decision', error: String(error.message ?? error) })) })
    this.dsh.on('permission-error', request => { void this.onPermissionTerminal(request, 'error').catch(error => this.emit('internal-error', { stage: 'permission.error', error: String(error.message ?? error) })) })
    this.dsh.on('process-exit', event => { void this.onDshProcessExit(event).catch(error => this.emit('internal-error', { stage: 'dsh.process-exit', error: String(error.message ?? error) })) })
    this.dsh.on('stderr', event => { void this.onDshStderr(event).catch(error => this.emit('internal-error', { stage: 'dsh.stderr', error: String(error.message ?? error) })) })
  }

  async open() {
    await this.store.open()
    for (const task of Object.values(this.store.state.tasks)) {
      if (['queued', 'running', 'waiting_permission', 'pausing', 'cancelling'].includes(task.status)) {
        task.status = 'needs_reconcile'
        task.error = 'bridge restarted while task was active; inspect the persisted evidence and explicitly resume or cancel'
        task.updatedAt = now()
        this.appendEventInMemory(task, 'bridge.restart_recovery', { error: task.error })
      }
    }
    await this.store.flush()
    return this
  }

  appendEventInMemory(task, kind, data) {
    const safeData = redactValue(data, this.config.limits.eventBytes)
    task.eventSeq = (task.eventSeq ?? 0) + 1
    task.events ??= []
    task.events.push({ seq: task.eventSeq, at: now(), kind, data: safeData })
    if (task.events.length > this.config.limits.taskEvents) task.events.splice(0, task.events.length - this.config.limits.taskEvents)
    task.updatedAt = now()
  }

  async appendEvent(taskId, kind, data) {
    return this.store.mutate(state => {
      const task = state.tasks[taskId]
      if (task === undefined) return undefined
      this.appendEventInMemory(task, kind, data)
      return clone(task.events.at(-1))
    })
  }

  async addEvidence({ taskId, kind, label, content }) {
    const id = newId('evidence')
    const safeContent = redactValue(content, this.config.limits.evidenceBytes)
    let record
    await this.store.mutate(state => {
      const task = state.tasks[taskId]
      if (task === undefined) throw errorWithCode(`unknown task: ${taskId}`, 'UNKNOWN_TASK')
      record = {
        id,
        taskId,
        planId: task.planId,
        planVersion: task.planVersion,
        planHash: task.planHash,
        executionRunId: task.executionRunId,
        kind,
        label: label ?? kind,
        createdAt: now(),
        content: safeContent,
        sha256: sha256(safeContent),
      }
      state.evidence[id] = record
      task.evidenceIds ??= []
      task.evidenceIds.push(id)
      task.updatedAt = now()
    })
    return clone(record)
  }

  async submitPlan(input) {
    const objective = text(input.objective, 'objective', { max: 12000 })
    const executionPrompt = text(input.executionPrompt, 'executionPrompt', { max: 50000 })
    const scope = input.scope
    if (scope === undefined || typeof scope !== 'object') throw new Error('scope is required')
    const workspace = await resolveWorkspaceScope(scope.workspace, this.config.workspaceRoot)
    const allowedPaths = await assertPathListAllowed(scope.allowedPaths, workspace, this.config.workspaceRoot)
    const executionCwd = await deriveExecutionCwd(workspace, allowedPaths)
    const operations = Array.isArray(scope.operations) ? [...new Set(scope.operations)] : []
    if (operations.length === 0 || operations.some(value => !OPERATIONS.has(value))) {
      throw new Error('scope.operations must contain only read, write, and execute')
    }
    const constraints = Array.isArray(input.constraints) ? input.constraints.map((value, index) => text(value, `constraints[${index}]`, { max: 4000 })) : []
    const rawCriteria = input.acceptanceCriteria
    if (!Array.isArray(rawCriteria) || rawCriteria.length === 0) throw new Error('acceptanceCriteria must contain at least one criterion')
    const acceptanceCriteria = rawCriteria.map((criterion, index) => {
      if (criterion === null || typeof criterion !== 'object') throw new Error(`acceptanceCriteria[${index}] must be an object`)
      return {
        id: text(criterion.id, `acceptanceCriteria[${index}].id`, { max: 120 }),
        description: text(criterion.description, `acceptanceCriteria[${index}].description`, { max: 4000 }),
        evidenceKinds: Array.isArray(criterion.evidenceKinds)
          ? [...new Set(criterion.evidenceKinds.map((value, kindIndex) => text(value, `acceptanceCriteria[${index}].evidenceKinds[${kindIndex}]`, { max: 120 })))]
          : [],
      }
    })
    const ids = new Set()
    for (const criterion of acceptanceCriteria) {
      if (ids.has(criterion.id)) throw new Error(`duplicate acceptance criterion id: ${criterion.id}`)
      ids.add(criterion.id)
    }

    const planId = input.planId === undefined ? newId('plan') : text(input.planId, 'planId', { max: 120 })
    const requestedVersion = input.version === undefined ? undefined : Number(input.version)
    const content = { planId, objective, scope: { workspace, allowedPaths, operations, executionCwd }, constraints, acceptanceCriteria, executionPrompt }
    let result
    await this.store.mutate(state => {
      const existing = state.plans[planId]
      const version = existing === undefined ? 1 : existing.latestVersion + 1
      if (requestedVersion !== undefined && requestedVersion !== version) {
        throw new Error(`plan version must be ${version} for ${planId}`)
      }
      const plan = {
        ...content,
        version,
        hash: sha256({ ...content, version }),
        status: 'proposed',
        createdAt: now(),
        approvals: [],
      }
      if (existing === undefined) state.plans[planId] = { latestVersion: version, versions: { [String(version)]: plan } }
      else {
        const previous = existing.versions[String(existing.latestVersion)]
        if (previous !== undefined && !['accepted', 'rejected', 'superseded'].includes(previous.status)) {
          previous.status = 'superseded'
          previous.supersededAt = now()
        }
        existing.latestVersion = version
        existing.versions[String(version)] = plan
      }
      result = clone(plan)
    })
    return result
  }

  async requestPlanApproval({ planId, version, reason }) {
    const approvalId = newId('approval')
    let result
    await this.store.mutate(state => {
      const plan = findPlanVersion(state, planId, version)
      if (plan.status === 'approved') {
        result = { status: 'already_approved', plan: clone(plan) }
        return
      }
      if (!['proposed', 'approval_pending', 'rejected'].includes(plan.status)) throw new Error(`plan cannot request approval from status ${plan.status}`)
      const existing = Object.values(state.approvals).find(item => item.planId === plan.planId && item.version === plan.version && item.status === 'pending')
      if (existing !== undefined) {
        result = { status: 'approval_pending', approval: clone(existing), plan: clone(plan) }
        return
      }
      const approval = {
        id: approvalId,
        planId: plan.planId,
        version: plan.version,
        planHash: plan.hash,
        requestedOperation: 'start_task_within_approved_plan',
        reason: reason === undefined ? '计划需要人工确认后才能执行' : text(reason, 'reason', { max: 4000 }),
        status: 'pending',
        createdAt: now(),
      }
      state.approvals[approvalId] = approval
      plan.status = 'approval_pending'
      plan.approvals.push(approvalId)
      result = { status: 'approval_pending', approval: clone(approval), plan: clone(plan) }
    })
    return result
  }

  async decideHumanApproval(approvalId, decision, comment) {
    let result
    await this.store.mutate(state => {
      const approval = state.approvals[approvalId]
      if (approval === undefined) throw new Error(`unknown approval: ${approvalId}`)
      if (approval.status !== 'pending') throw new Error(`approval is already ${approval.status}`)
      const plan = findPlanVersion(state, approval.planId, approval.version)
      if (plan.hash !== approval.planHash) throw new Error('plan hash changed; approval is invalid')
      if (latestPlan(state, approval.planId).version !== plan.version) throw new Error('a newer plan version exists; approval is invalid')
      if (!['approve', 'reject'].includes(decision)) throw new Error('decision must be approve or reject')
      approval.status = decision === 'approve' ? 'approved' : 'rejected'
      approval.comment = comment === undefined ? undefined : text(comment, 'comment', { max: 4000 })
      approval.decidedAt = now()
      plan.status = decision === 'approve' ? 'approved' : 'rejected'
      plan.updatedAt = now()
      result = { approval: clone(approval), plan: clone(plan) }
    })
    return result
  }

  async getPlan(planId, version) {
    return this.store.mutate(state => clone(findPlanVersion(state, planId, version)))
  }

  async startTask(input) {
    const taskId = input.taskId === undefined ? newId('task') : text(input.taskId, 'taskId', { max: 120 })
    let task
    let idempotent = false
    await this.store.mutate(async state => {
      const plan = findPlanVersion(state, input.planId, input.version)
      if (plan.status !== 'approved') throw new Error(`plan must be human-approved before start; current status=${plan.status}`)
      if (plan.scope.executionCwd === undefined) throw errorWithCode('plan has no enforceable DSH execution boundary; submit a new plan version', 'SCOPE_NOT_ENFORCEABLE')
      if (this.config.dsh.permissionMode === 'danger-full-access') {
        throw errorWithCode('DSH_PERMISSION_MODE=danger-full-access is not allowed for bridge-controlled tasks', 'DSH_POLICY_TOO_BROAD')
      }
      const planMayMutate = plan.scope.operations.some(operation => ['write', 'execute'].includes(operation))
      if (planMayMutate && this.config.dsh.permissionMode === 'read-only') {
        throw errorWithCode('the approved plan requires write access but DSH is configured read-only', 'DSH_POLICY_TOO_NARROW')
      }
      if (!planMayMutate && this.config.dsh.permissionMode === 'workspace-write') {
        throw errorWithCode('a read-only plan cannot run under the broader workspace-write DSH mode', 'DSH_POLICY_TOO_BROAD')
      }
      const existingById = state.tasks[taskId]
      if (existingById !== undefined) {
        if (existingById.planId !== plan.planId || existingById.planVersion !== plan.version || existingById.planHash !== plan.hash) {
          throw errorWithCode(`taskId is already assigned to another plan: ${taskId}`, 'TASK_ID_CONFLICT')
        }
        task = clone(existingById)
        idempotent = true
        return
      }
      const existing = Object.values(state.tasks).find(item => item.planId === plan.planId && ACTIVE_TASK_STATUSES.has(item.status))
      if (existing !== undefined) throw new Error(`plan already has an active or review task: ${existing.id}`)
      task = {
        id: taskId,
        planId: plan.planId,
        planVersion: plan.version,
        planHash: plan.hash,
        workspace: plan.scope.workspace,
        allowedPaths: plan.scope.allowedPaths,
        operations: plan.scope.operations,
        executionCwd: plan.scope.executionCwd,
        status: 'queued',
        createdAt: now(),
        updatedAt: now(),
        eventSeq: 0,
        events: [],
        evidenceIds: [],
        assistantOutput: '',
        correctionCount: 0,
      }
      state.tasks[taskId] = task
      this.appendEventInMemory(task, 'task.queued', { planId: plan.planId, version: plan.version, planHash: plan.hash })
    })
    if (idempotent) return this.getTask(taskId)
    try {
      const before = await captureWorkspaceSnapshot(task.workspace, this.config.limits, { allowedPaths: task.allowedPaths })
      const evidence = await this.addEvidence({ taskId, kind: 'workspace.before', label: '执行前工作区状态', content: before })
      await this.store.mutate(state => {
        const current = state.tasks[taskId]
        if (current !== undefined) current.workspaceBeforeEvidenceId = evidence.id
      })
      await this.appendEvent(taskId, 'evidence.workspace_before', { captured: true })
    } catch (error) {
      await this.appendEvent(taskId, 'evidence.workspace_before_failed', { error: error.message })
    }
    void this.runTaskPrompt(taskId, undefined).catch(error => this.emit('internal-error', { stage: 'task.run', error: String(error?.message ?? error) }))
    return this.getTask(taskId)
  }

  buildPrompt(plan, task, extra) {
    const scope = JSON.stringify(plan.scope)
    const criteria = plan.acceptanceCriteria.map(item => `- ${item.id}: ${item.description}`).join('\n')
    return [
      `You are the execution worker for bridge task ${task.id}.`,
      'Execute only the approved plan below. Do not widen paths, operations, constraints, or acceptance criteria.',
      `Approved plan hash: ${plan.hash}`,
      `Objective: ${plan.objective}`,
      `Scope: ${scope}`,
      `Constraints:\n${plan.constraints.map(item => `- ${item}`).join('\n') || '- none'}`,
      `Acceptance criteria:\n${criteria}`,
      `Execution instructions:\n${plan.executionPrompt}`,
      extra === undefined ? '' : `\nCorrection or continuation request:\n${extra}`,
      'At the end, report the commands run, exit status, files changed, tests and raw relevant output. A report is not proof by itself; leave the workspace and session evidence available for inspection.',
    ].filter(Boolean).join('\n\n')
  }

  async finalizeRequestedStop(taskId, runId, sessionId) {
    if (sessionId !== undefined) {
      try { await this.dsh.cancel(sessionId) } catch { /* the prompt may already have stopped */ }
    }
    let changed = false
    await this.store.mutate(state => {
      const task = state.tasks[taskId]
      if (task === undefined || task.executionRunId !== runId) return
      const status = task.cancelRequested === true ? 'cancelled' : (task.pauseRequested === true ? 'paused' : undefined)
      if (status === undefined) return
      task.status = status
      delete task.cancelRequested
      delete task.pauseRequested
      task.pendingPermissionId = undefined
      task.pendingPermission = undefined
      this.appendEventInMemory(task, `task.${status}`, { runId, confirmedBeforePrompt: true })
      changed = true
    })
    if (changed) this.emit('task-updated', { taskId })
  }

  async canPrompt(taskId, runId, sessionId) {
    return this.store.mutate(state => {
      const task = state.tasks[taskId]
      if (task === undefined || task.executionRunId !== runId) return false
      if (task.dshSessionId === undefined) {
        task.dshSessionId = sessionId
        this.appendEventInMemory(task, 'dsh.session_created', { sessionId })
      }
      return task.status === 'running' && task.cancelRequested !== true && task.pauseRequested !== true
    })
  }

  async runTaskPrompt(taskId, extra) {
    const runId = newId('run')
    let task
    let plan
    let shouldRun = true
    try {
      await this.store.mutate(state => {
      task = state.tasks[taskId]
      if (task === undefined) throw errorWithCode(`unknown task: ${taskId}`, 'UNKNOWN_TASK')
      plan = findPlanVersion(state, task.planId, task.planVersion)
      if (!RUNNABLE_TASK_STATUSES.has(task.status)) throw new Error(`task cannot run from status ${task.status}`)
      if (task.cancelRequested === true) {
        task.status = 'cancelled'
        delete task.cancelRequested
        shouldRun = false
        this.appendEventInMemory(task, 'task.cancelled_before_run', { runId })
        return
      }
      task.executionRunId = runId
      task.status = 'running'
      task.pendingPermissionId = undefined
      this.appendEventInMemory(task, 'task.running', { correction: extra !== undefined, runId })
      })
      if (!shouldRun) return

      let sessionId = task.dshSessionId
      if (sessionId === undefined) {
        sessionId = await this.dsh.createSession(task.executionCwd)
      } else {
        await this.dsh.ensureSession(sessionId, task.executionCwd)
      }
      if (!await this.canPrompt(taskId, runId, sessionId)) {
        await this.finalizeRequestedStop(taskId, runId, sessionId)
        return
      }
      const result = await this.dsh.prompt(sessionId, this.buildPrompt(plan, task, extra))
      await this.finishTaskPrompt(taskId, result, runId)
    } catch (error) {
      await this.failTask(taskId, error, runId)
    }
  }

  async finishTaskPrompt(taskId, result, runId) {
    let task
    await this.store.mutate(state => {
      task = state.tasks[taskId]
      if (task === undefined || task.executionRunId !== runId) return
      task.stopReason = STOP_REASONS.has(result.stopReason) ? result.stopReason : 'unknown'
      task.assistantOutput = capText(redactText(result.assistantText), this.config.limits.evidenceBytes)
      task.pendingPermissionId = undefined
      if (task.pauseRequested === true) {
        task.status = 'paused'
        delete task.pauseRequested
      } else if (task.cancelRequested === true || result.stopReason === 'cancelled') {
        task.status = task.cancelRequested === true ? 'cancelled' : 'failed'
        delete task.cancelRequested
      } else if (result.stopReason === 'end_turn' || result.stopReason === 'max_tokens') {
        task.status = 'waiting_review'
      } else {
        task.status = 'failed'
        task.error = `DSH prompt stopped with ${result.stopReason}`
      }
      this.appendEventInMemory(task, 'dsh.prompt_finished', { stopReason: task.stopReason, assistantOutput: task.assistantOutput, status: task.status })
    })
    if (task === undefined || task.executionRunId !== runId) return
    await this.addEvidence({ taskId, kind: 'dsh.prompt_result', label: 'DSH ACP 提示词结果', content: { stopReason: result.stopReason, assistantOutput: result.assistantText } })
    let before
    try {
      if (task.workspaceBeforeEvidenceId !== undefined) {
        before = await this.getEvidence(task.workspaceBeforeEvidenceId).then(evidence => evidence.content).catch(() => undefined)
      }
      const after = await captureWorkspaceSnapshot(task.workspace, this.config.limits, { allowedPaths: task.allowedPaths })
      await this.addEvidence({ taskId, kind: 'workspace.after', label: '执行后工作区状态', content: after })
      await this.addEvidence({ taskId, kind: 'workspace.delta', label: '执行期间工作区总变更', content: await captureWorkspaceDelta(before, after, this.config.limits) })
      await this.appendEvent(taskId, 'evidence.workspace_after', { captured: true })
    } catch (error) {
      await this.appendEvent(taskId, 'evidence.workspace_after_failed', { error: error.message })
    }
    const finalTask = await this.getTask(taskId)
    await this.addEvidence({ taskId, kind: 'task.event_log', label: '桥接任务事件索引', content: finalTask })
    this.emit('task-updated', { taskId })
  }

  async failTask(taskId, error, runId) {
    const failedTask = await this.getTask(taskId).catch(() => undefined)
    let handled = false
    await this.store.mutate(state => {
      const task = state.tasks[taskId]
      if (task === undefined) return
      if (runId !== undefined && task.executionRunId !== runId) return
      handled = true
      task.status = task.cancelRequested === true ? 'cancelled' : 'failed'
      if (task.pauseRequested === true) task.status = 'paused'
      task.error = redactText(error?.message ?? error)
      delete task.cancelRequested
      delete task.pauseRequested
      task.pendingPermissionId = undefined
      this.appendEventInMemory(task, 'task.failed', { error: task.error })
    })
    if (!handled) return
    await this.addEvidence({ taskId, kind: 'task.failure', label: '任务失败记录', content: { error: redactText(error?.message ?? error), priorTask: failedTask } })
    if (failedTask !== undefined) {
      try {
        const after = await captureWorkspaceSnapshot(failedTask.workspace, this.config.limits, { allowedPaths: failedTask.allowedPaths })
        await this.addEvidence({ taskId, kind: 'workspace.after_failure', label: '失败后的工作区状态', content: after })
      } catch (snapshotError) {
        await this.appendEvent(taskId, 'evidence.workspace_after_failure_failed', { error: snapshotError.message })
      }
    }
    this.emit('task-updated', { taskId })
  }

  async pauseTask(taskId) {
    const task = await this.getTask(taskId)
    if (!['running', 'waiting_permission'].includes(task.status)) throw new Error(`task cannot pause from status ${task.status}`)
    await this.store.mutate(state => {
      const current = state.tasks[taskId]
      current.pauseRequested = true
      current.status = 'pausing'
      this.appendEventInMemory(current, 'task.pause_requested', { reason: 'user requested pause' })
    })
    if (task.dshSessionId !== undefined) await this.dsh.cancel(task.dshSessionId)
    return this.getTask(taskId)
  }

  async resumeTask(taskId) {
    const task = await this.getTask(taskId)
    if (!['paused', 'needs_reconcile'].includes(task.status)) throw new Error(`task cannot resume from status ${task.status}`)
    await this.store.mutate(state => {
      const current = state.tasks[taskId]
      const plan = findPlanVersion(state, current.planId, current.planVersion)
      if (plan.status !== 'approved') throw new Error('the plan is no longer approved')
      delete current.pauseRequested
      delete current.cancelRequested
      current.status = 'queued'
      this.appendEventInMemory(current, 'task.resume_requested', { reconciled: task.status === 'needs_reconcile' })
    })
    void this.runTaskPrompt(taskId, 'Resume the approved plan from the current workspace state. Do not replay already completed work unless needed to verify it.')
      .catch(error => this.emit('internal-error', { stage: 'task.resume', error: String(error?.message ?? error) }))
    return this.getTask(taskId)
  }

  async cancelTask(taskId) {
    const task = await this.getTask(taskId)
    if (['accepted', 'cancelled', 'failed'].includes(task.status)) return task
    await this.store.mutate(state => {
      const current = state.tasks[taskId]
      current.cancelRequested = true
      if (current.executionRunId === undefined && current.dshSessionId === undefined && current.status === 'queued') {
        current.status = 'cancelled'
        delete current.cancelRequested
      } else {
        current.status = 'cancelling'
      }
      this.appendEventInMemory(current, 'task.cancel_requested', {})
    })
    if (task.dshSessionId !== undefined) await this.dsh.cancel(task.dshSessionId)
    return this.getTask(taskId)
  }

  async sendCorrection({ taskId, correction }) {
    const request = text(correction, 'correction', { max: 20000 })
    const task = await this.getTask(taskId)
    if (!['waiting_review', 'rework_required'].includes(task.status)) throw new Error(`task cannot accept correction from status ${task.status}`)
    await this.store.mutate(state => {
      const current = state.tasks[taskId]
      delete current.pauseRequested
      delete current.cancelRequested
      current.correctionCount += 1
      current.status = 'queued'
      this.appendEventInMemory(current, 'task.correction_requested', { correction: request, correctionCount: current.correctionCount })
    })
    void this.runTaskPrompt(taskId, request).catch(error => this.emit('internal-error', { stage: 'task.correction', error: String(error?.message ?? error) }))
    return this.getTask(taskId)
  }

  async recordAcceptance({ taskId, criteria, summary }) {
    if (!Array.isArray(criteria) || criteria.length === 0) throw new Error('criteria must contain at least one result')
    const task = await this.getTask(taskId)
    if (task.status !== 'waiting_review') throw new Error(`task is not waiting for review: ${task.status}`)
    let result
    await this.store.mutate(state => {
      const current = state.tasks[taskId]
      const plan = findPlanVersion(state, current.planId, current.planVersion)
      const expected = new Map(plan.acceptanceCriteria.map(item => [item.id, item]))
      const seen = new Set()
      const normalized = criteria.map(item => {
        if (item === null || typeof item !== 'object') throw new Error('criteria entries must be objects')
        const id = text(item.id, 'criteria.id', { max: 120 })
        if (!expected.has(id) || seen.has(id)) throw new Error(`criteria must contain each plan criterion exactly once: ${id}`)
        seen.add(id)
        const outcome = item.result
        if (!['pass', 'fail', 'unverified'].includes(outcome)) throw new Error(`invalid criterion result for ${id}`)
        const evidenceIds = Array.isArray(item.evidenceIds) ? item.evidenceIds.map(value => text(value, 'evidenceIds[]', { max: 160 })) : []
        for (const evidenceId of evidenceIds) {
          const evidence = state.evidence[evidenceId]
          if (evidence === undefined || evidence.taskId !== taskId || evidence.planHash !== current.planHash || evidence.executionRunId !== current.executionRunId) {
            throw new Error(`evidence does not belong to the current task execution: ${evidenceId}`)
          }
        }
        const criterion = expected.get(id)
        if (outcome === 'pass' && evidenceIds.length === 0) throw new Error(`passing criterion requires evidence: ${id}`)
        if (outcome === 'pass' && Array.isArray(criterion.evidenceKinds) && criterion.evidenceKinds.length > 0) {
          const kinds = new Set(evidenceIds.map(evidenceId => state.evidence[evidenceId].kind))
          if (criterion.evidenceKinds.some(kind => !kinds.has(kind))) {
            throw new Error(`passing criterion is missing required evidence kind: ${id}`)
          }
        }
        return { id, result: outcome, evidenceIds, note: item.note === undefined ? undefined : text(item.note, 'criteria.note', { max: 4000 }) }
      })
      if (seen.size !== expected.size) throw new Error('criteria must cover every acceptance criterion')
      const allPass = normalized.every(item => item.result === 'pass')
      const anyFail = normalized.some(item => item.result === 'fail')
      current.acceptance = { recordedAt: now(), summary: summary === undefined ? undefined : text(summary, 'summary', { max: 8000 }), criteria: normalized }
      current.status = allPass ? 'accepted' : (anyFail ? 'rework_required' : 'waiting_review')
      this.appendEventInMemory(current, 'acceptance.recorded', { status: current.status, acceptance: current.acceptance })
      result = clone({ task: current, accepted: allPass })
    })
    await this.addEvidence({ taskId, kind: 'acceptance.record', label: '验收记录', content: result.task.acceptance })
    return this.getTask(taskId)
  }

  async decidePermission({ taskId, permissionId, allow, optionId }) {
    const task = await this.getTask(taskId)
    if (task.pendingPermissionId !== permissionId) throw new Error('permission is not pending for this task')
    if (task.status !== 'waiting_permission') throw new Error(`task is not waiting for a permission decision: ${task.status}`)
    const pending = task.pendingPermission
    if (pending?.sessionId !== task.dshSessionId) throw new Error('permission session does not match the task session')
    if (allow === true) {
      const plan = await this.getPlan(task.planId, task.planVersion)
      if (plan.status !== 'approved' || latestPlan((await this.store.snapshot()), task.planId).version !== task.planVersion) {
        throw new Error('permission requires the currently approved plan version')
      }
      const operation = operationForToolCall(pending?.toolCall)
      if (operation === 'unknown') {
        this.dsh.decidePermission(permissionId, { allow: false })
        await this.clearPendingPermission(taskId, permissionId, 'permission.denied_unknown_tool')
        throw errorWithCode('permission denied because the ACP tool shape is unknown', 'UNKNOWN_TOOL_SHAPE')
      }
      if (!plan.scope.operations.includes(operation)) {
        this.dsh.decidePermission(permissionId, { allow: false })
        await this.clearPendingPermission(taskId, permissionId, 'permission.denied_scope', { operation, toolKind: pending?.toolCall?.kind })
        throw errorWithCode(`permission denied because plan does not allow operation: ${operation}`, 'PERMISSION_OUT_OF_SCOPE')
      }
      const pathCheck = toolCallWithinScope(pending?.toolCall, plan.scope.allowedPaths, plan.scope.executionCwd)
      if (!pathCheck.ok) {
        this.dsh.decidePermission(permissionId, { allow: false })
        await this.clearPendingPermission(taskId, permissionId, 'permission.denied_path', { path: pathCheck.value })
        throw errorWithCode(`permission denied because the tool path is outside the approved scope: ${pathCheck.value}`, 'PERMISSION_OUT_OF_SCOPE')
      }
    }
    const request = this.dsh.decidePermission(permissionId, { allow, optionId })
    await this.store.mutate(state => {
      const current = state.tasks[taskId]
      current.pendingPermissionId = undefined
      current.pendingPermission = undefined
      this.appendEventInMemory(current, 'permission.decided', { allow: allow === true, optionId, toolKind: request.toolCall.kind })
      if (current.status === 'waiting_permission') current.status = 'running'
    })
    return this.getTask(taskId)
  }

  async clearPendingPermission(taskId, permissionId, eventKind, data = {}) {
    await this.store.mutate(state => {
      const current = state.tasks[taskId]
      if (current === undefined || current.pendingPermissionId !== permissionId) return
      current.pendingPermissionId = undefined
      current.pendingPermission = undefined
      if (current.status === 'waiting_permission') current.status = 'running'
      this.appendEventInMemory(current, eventKind, data)
    })
  }

  async getTask(taskId) {
    return this.store.mutate(state => {
      const task = state.tasks[taskId]
      if (task === undefined) throw new Error(`unknown task: ${taskId}`)
      return clone(task)
    })
  }

  async getEvidence(evidenceId) {
    return this.store.mutate(state => {
      const evidence = state.evidence[evidenceId]
      if (evidence === undefined) throw new Error(`unknown evidence: ${evidenceId}`)
      return clone(evidence)
    })
  }

  async getApproval(approvalId) {
    return this.store.mutate(state => {
      const approval = state.approvals[approvalId]
      if (approval === undefined) throw new Error(`unknown approval: ${approvalId}`)
      return clone(approval)
    })
  }

  async getPermission(permissionId) {
    return this.store.mutate(state => {
      const task = Object.values(state.tasks).find(item => item.pendingPermissionId === permissionId)
      if (task === undefined) throw new Error(`unknown or expired permission: ${permissionId}`)
      return {
        taskId: task.id,
        planId: task.planId,
        planVersion: task.planVersion,
        planHash: task.planHash,
        status: task.status,
        permission: clone(task.pendingPermission),
      }
    })
  }

  async inspectWorkspace(workspace) {
    const normalized = await resolveWorkspaceScope(workspace, this.config.workspaceRoot)
    return captureWorkspaceSnapshot(normalized, this.config.limits, { allowedPaths: [normalized] })
  }

  async inspectDsh({ includeSessions = false, cwd } = {}) {
    const status = this.dsh.status()
    if (!includeSessions) return status
    try {
      const sessions = await this.dsh.listSessions(cwd)
      return { ...this.dsh.status(), sessions }
    } catch (error) {
      return { ...this.dsh.status(), sessionListError: redactText(error.message) }
    }
  }

  health() {
    const state = this.store.state
    return {
      service: 'dsh-chatgpt-bridge',
      version: '0.1.0',
      dsh: this.dsh.status(),
      counts: {
        plans: Object.values(state.plans).reduce((sum, item) => sum + Object.keys(item.versions).length, 0),
        tasks: Object.keys(state.tasks).length,
        evidence: Object.keys(state.evidence).length,
        approvals: Object.keys(state.approvals).length,
      },
    }
  }

  async onDshUpdate(update) {
    if (update.sessionId === undefined) return
    await this.store.mutate(state => {
      const task = taskBySession(state, update.sessionId)
      if (task === undefined) return
      const sessionUpdate = update.update
      if (sessionUpdate?.sessionUpdate === 'tool_call' && typeof sessionUpdate.toolCallId === 'string' && task.pendingPermission?.toolCall?.toolCallId === sessionUpdate.toolCallId) {
        task.pendingPermission.toolCall = {
          ...task.pendingPermission.toolCall,
          name: sessionUpdate.title,
          title: sessionUpdate.title,
          kind: sessionUpdate.kind,
          rawInput: redactValue(sessionUpdate.rawInput, this.config.limits.eventBytes),
        }
      }
      this.appendEventInMemory(task, 'dsh.session_update', update)
    })
    this.emit('task-updated', { sessionId: update.sessionId })
  }

  async onPermissionRequest(request) {
    await this.store.mutate(state => {
      const task = taskBySession(state, request.sessionId)
      if (task === undefined || task.cancelRequested === true || task.pauseRequested === true || task.status === 'cancelling' || task.status === 'pausing') {
        try { this.dsh.decidePermission(request.permissionId, { allow: false }) } catch { /* the request may have expired */ }
        return
      }
      task.status = 'waiting_permission'
      task.pendingPermissionId = request.permissionId
      task.pendingPermission = redactValue(request, this.config.limits.eventBytes)
      this.appendEventInMemory(task, 'permission.requested', task.pendingPermission)
    })
    this.emit('task-updated', { sessionId: request.sessionId, permissionId: request.permissionId })
  }

  async onPermissionTerminal(request, decision) {
    await this.store.mutate(state => {
      const task = taskBySession(state, request.sessionId)
      if (task === undefined) return
      if (task.pendingPermissionId === request.permissionId && (decision === 'timeout' || decision === 'error')) {
        task.pendingPermissionId = undefined
        task.pendingPermission = undefined
        if (task.status === 'waiting_permission') task.status = 'running'
      }
      this.appendEventInMemory(task, `permission.${decision}`, { permissionId: request.permissionId })
    })
  }

  async onDshProcessExit(event) {
    await this.store.mutate(state => {
      for (const task of Object.values(state.tasks)) {
        if (['queued', 'running', 'waiting_permission', 'pausing', 'cancelling'].includes(task.status)) {
          task.status = task.cancelRequested === true ? 'cancelled' : (task.pauseRequested === true ? 'paused' : 'failed')
          task.error = redactText(event.message)
          task.pendingPermissionId = undefined
          task.pendingPermission = undefined
          delete task.cancelRequested
          delete task.pauseRequested
          this.appendEventInMemory(task, 'dsh.process_exit', event)
        }
      }
    })
    this.emit('dsh-process-exit', event)
  }

  async onDshStderr(event) {
    await this.store.mutate(state => {
      for (const task of Object.values(state.tasks)) {
        if (['queued', 'running', 'waiting_permission', 'pausing', 'cancelling'].includes(task.status)) this.appendEventInMemory(task, 'dsh.stderr', event)
      }
    })
  }
}
