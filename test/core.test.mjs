import test, { afterEach } from 'node:test'
import assert from 'node:assert/strict'
import { EventEmitter } from 'node:events'
import { mkdir, mkdtemp, rm } from 'node:fs/promises'
import { join } from 'node:path'
import { tmpdir } from 'node:os'
import { loadConfig } from '../src/config.mjs'
import { BridgeCore } from '../src/core.mjs'
import { JsonStore } from '../src/persistence.mjs'

const temporaryRoots = []

class FakeDsh extends EventEmitter {
  constructor() {
    super()
    this.createCalls = []
    this.ensureCalls = []
    this.promptCalls = []
    this.cancelCalls = []
    this.permissionDecisions = []
    this.promptResult = { stopReason: 'end_turn', assistantText: 'fake evidence' }
    this.createStarted = Promise.resolve()
    this.createGate = undefined
    this.promptGate = undefined
    this.nextSessionId = 'session-1'
  }

  async createSession(cwd) {
    this.createCalls.push(cwd)
    if (this.createGate !== undefined) {
      let resolveStarted
      this.createStarted = new Promise(resolve => { resolveStarted = resolve })
      resolveStarted()
      return this.createGate.promise
    }
    return this.nextSessionId
  }

  async ensureSession(sessionId, cwd) {
    this.ensureCalls.push({ sessionId, cwd })
    return sessionId
  }

  async prompt(sessionId, prompt) {
    this.promptCalls.push({ sessionId, prompt })
    if (this.promptGate !== undefined) return this.promptGate.promise
    return this.promptResult
  }

  async cancel(sessionId) {
    this.cancelCalls.push(sessionId)
  }

  decidePermission(permissionId, decision) {
    this.permissionDecisions.push({ permissionId, ...decision })
    return { toolCall: { kind: 'edit' } }
  }

  status() {
    return { connected: false, activeSessionCount: 0, pendingPermissionCount: 0 }
  }

  async listSessions() {
    return []
  }
}

function deferred() {
  let resolve
  let reject
  const promise = new Promise((resolvePromise, rejectPromise) => {
    resolve = resolvePromise
    reject = rejectPromise
  })
  return { promise, resolve, reject }
}

async function waitFor(predicate, timeoutMs = 2000) {
  const deadline = Date.now() + timeoutMs
  while (Date.now() < deadline) {
    if (await predicate()) return
    await new Promise(resolve => setTimeout(resolve, 10))
  }
  assert.fail('condition was not reached before timeout')
}

async function makeCore({ maxTaskEvents } = {}) {
  const root = await mkdtemp(join(tmpdir(), 'dsh-bridge-core-'))
  temporaryRoots.push(root)
  const workspace = join(root, 'workspace')
  await mkdir(workspace)
  const env = {
    ...process.env,
    BRIDGE_WORKSPACE_ROOT: root,
    BRIDGE_DATA_DIR: join(root, 'data'),
    BRIDGE_AUTH_MODE: 'both',
    BRIDGE_OAUTH_ENABLED: '1',
    BRIDGE_INSPECT_TOKEN: 'inspect',
    BRIDGE_CONTROL_TOKEN: 'control',
    BRIDGE_HUMAN_APPROVAL_TOKEN: 'human',
    BRIDGE_OAUTH_LOGIN_TOKEN: 'login',
    DSH_PERMISSION_MODE: 'read-only',
    DSH_COMMAND: process.execPath,
    DSH_ARGS: '',
    ...(maxTaskEvents === undefined ? {} : { BRIDGE_MAX_TASK_EVENTS: String(maxTaskEvents) }),
  }
  const config = loadConfig({ cwd: root, env })
  const store = await new JsonStore(join(root, 'data', 'state.json')).open()
  const dsh = new FakeDsh()
  const core = await new BridgeCore({ config, store, dsh }).open()
  return { root, workspace, config, store, dsh, core }
}

async function approvedPlan(core, workspace, {
  planId,
  operations = ['read'],
  allowedPaths = [workspace],
  evidenceKinds = [],
} = {}) {
  const plan = await core.submitPlan({
    planId,
    objective: 'test objective',
    scope: { workspace, allowedPaths, operations },
    constraints: [],
    acceptanceCriteria: [{ id: 'c1', description: 'a verifiable result', evidenceKinds }],
    executionPrompt: 'perform the test task',
  })
  const requested = await core.requestPlanApproval({ planId: plan.planId, version: plan.version })
  await core.decideHumanApproval(requested.approval.id, 'approve')
  return core.getPlan(plan.planId, plan.version)
}

afterEach(async () => {
  while (temporaryRoots.length > 0) await rm(temporaryRoots.pop(), { recursive: true, force: true })
})

test('cancellation during delayed session creation never starts a prompt', async () => {
  const { core, workspace, dsh } = await makeCore()
  const plan = await approvedPlan(core, workspace)
  const gate = deferred()
  dsh.createGate = gate
  const started = await core.startTask({ planId: plan.planId, version: plan.version, taskId: 'cancel-race' })
  await dsh.createStarted

  const cancelling = await core.cancelTask(started.id)
  assert.equal(cancelling.status, 'cancelling')
  gate.resolve('session-cancel-race')

  await waitFor(async () => (await core.getTask(started.id)).status === 'cancelled')
  assert.deepEqual(dsh.promptCalls, [])
  assert.deepEqual(dsh.cancelCalls, ['session-cancel-race'])
})

test('pause during delayed session creation never starts a prompt', async () => {
  const { core, workspace, dsh } = await makeCore()
  const plan = await approvedPlan(core, workspace)
  const gate = deferred()
  dsh.createGate = gate
  const started = await core.startTask({ planId: plan.planId, version: plan.version, taskId: 'pause-race' })
  await dsh.createStarted

  const pausing = await core.pauseTask(started.id)
  assert.equal(pausing.status, 'pausing')
  gate.resolve('session-pause-race')

  await waitFor(async () => (await core.getTask(started.id)).status === 'paused')
  assert.deepEqual(dsh.promptCalls, [])
  assert.deepEqual(dsh.cancelCalls, ['session-pause-race'])
})

test('passing acceptance criteria requires current-run evidence', async () => {
  const { core, workspace } = await makeCore()
  const plan = await approvedPlan(core, workspace, { evidenceKinds: ['workspace.after'] })
  const started = await core.startTask({ planId: plan.planId, version: plan.version, taskId: 'acceptance-evidence' })
  await waitFor(async () => {
    const current = await core.getTask(started.id)
    return current.status === 'waiting_review' && current.evidenceIds.some(id => core.store.state.evidence[id]?.kind === 'workspace.after')
  })
  const task = await core.getTask(started.id)

  await assert.rejects(
    core.recordAcceptance({ taskId: task.id, criteria: [{ id: 'c1', result: 'pass' }] }),
    /requires evidence/,
  )

  const evidence = task.evidenceIds
    .map(id => core.store.state.evidence[id])
    .find(item => item.executionRunId === task.executionRunId && item.kind === 'workspace.after')
  assert.ok(evidence)
  const accepted = await core.recordAcceptance({
    taskId: task.id,
    criteria: [{ id: 'c1', result: 'pass', evidenceIds: [evidence.id] }],
  })
  assert.equal(accepted.status, 'accepted')
})

test('task ids are idempotent for the same plan and rejected across plans', async () => {
  const { core, workspace } = await makeCore()
  const first = await approvedPlan(core, workspace, { planId: 'plan-a' })
  const second = await approvedPlan(core, workspace, { planId: 'plan-b' })
  const original = await core.startTask({ planId: first.planId, version: first.version, taskId: 'stable-task-id' })
  const retry = await core.startTask({ planId: first.planId, version: first.version, taskId: 'stable-task-id' })
  assert.equal(retry.id, original.id)
  await assert.rejects(
    core.startTask({ planId: second.planId, version: second.version, taskId: 'stable-task-id' }),
    error => error.code === 'TASK_ID_CONFLICT',
  )
  await waitFor(async () => {
    const current = await core.getTask(original.id)
    return current.status === 'waiting_review' && current.evidenceIds.some(id => core.store.state.evidence[id]?.kind === 'task.event_log')
  })
})

test('permission checks resolve relative paths and reject sandbox upgrades', async () => {
  const { core, workspace, dsh, store } = await makeCore()
  const allowed = join(workspace, 'allowed')
  const outside = join(workspace, 'outside')
  await mkdir(allowed)
  await mkdir(outside)
  const plan = await approvedPlan(core, workspace, { operations: ['write', 'execute'], allowedPaths: [allowed] })
  store.state.tasks['permission-scope-test'] = {
    id: 'permission-scope-test',
    planId: plan.planId,
    planVersion: plan.version,
    planHash: plan.hash,
    workspace,
    allowedPaths: [allowed],
    executionCwd: allowed,
    executionRunId: 'run-scope',
    status: 'waiting_permission',
    dshSessionId: 'permission-session',
    pendingPermissionId: 'permission-relative',
    pendingPermission: {
      permissionId: 'permission-relative',
      sessionId: 'permission-session',
      toolCall: { toolCallId: 'call-relative', kind: 'edit', name: 'write', rawInput: { file_path: '../outside.txt', sandbox_permissions: 'read-only' } },
    },
    events: [],
    evidenceIds: [],
    eventSeq: 0,
  }
  await assert.rejects(
    core.decidePermission({ taskId: 'permission-scope-test', permissionId: 'permission-relative', allow: true, optionId: 'allow-once' }),
    error => error.code === 'PERMISSION_OUT_OF_SCOPE',
  )
  assert.deepEqual(dsh.permissionDecisions, [{ permissionId: 'permission-relative', allow: false }])

  store.state.tasks['permission-scope-test'].status = 'waiting_permission'
  store.state.tasks['permission-scope-test'].pendingPermissionId = 'permission-upgrade'
  store.state.tasks['permission-scope-test'].pendingPermission = {
    permissionId: 'permission-upgrade',
    sessionId: 'permission-session',
    toolCall: { toolCallId: 'call-upgrade', kind: 'edit', name: 'write', rawInput: { file_path: 'inside.txt', sandbox_permissions: 'danger-full-access' } },
  }
  await assert.rejects(
    core.decidePermission({ taskId: 'permission-scope-test', permissionId: 'permission-upgrade', allow: true, optionId: 'allow-once' }),
    error => error.code === 'PERMISSION_OUT_OF_SCOPE',
  )
  assert.deepEqual(dsh.permissionDecisions, [
    { permissionId: 'permission-relative', allow: false },
    { permissionId: 'permission-upgrade', allow: false },
  ])

  store.state.tasks['permission-scope-test'].status = 'waiting_permission'
  store.state.tasks['permission-scope-test'].pendingPermissionId = 'permission-command'
  store.state.tasks['permission-scope-test'].pendingPermission = {
    permissionId: 'permission-command',
    sessionId: 'permission-session',
    toolCall: { toolCallId: 'call-command', kind: 'execute', name: 'shell', rawInput: { command: 'write ../outside.txt', sandbox_permissions: 'read-only' } },
  }
  await assert.rejects(
    core.decidePermission({ taskId: 'permission-scope-test', permissionId: 'permission-command', allow: true, optionId: 'allow-once' }),
    error => error.code === 'PERMISSION_OUT_OF_SCOPE',
  )
  assert.deepEqual(dsh.permissionDecisions, [
    { permissionId: 'permission-relative', allow: false },
    { permissionId: 'permission-upgrade', allow: false },
    { permissionId: 'permission-command', allow: false },
  ])
})

test('unsupported multiple-path scopes fail closed before approval', async () => {
  const { core, workspace } = await makeCore()
  const first = join(workspace, 'first')
  const second = join(workspace, 'second')
  await mkdir(first)
  await mkdir(second)
  await assert.rejects(
    core.submitPlan({
      objective: 'narrow scope',
      scope: { workspace, allowedPaths: [first, second], operations: ['write'] },
      constraints: [],
      acceptanceCriteria: [{ id: 'c1', description: 'result' }],
      executionPrompt: 'write only in the two directories',
    }),
    error => error.code === 'SCOPE_NOT_ENFORCEABLE',
  )
})

test('mutating plans cannot start under read-only DSH mode', async () => {
  const { core, workspace } = await makeCore()
  const plan = await approvedPlan(core, workspace, { operations: ['write'] })
  await assert.rejects(
    core.startTask({ planId: plan.planId, version: plan.version, taskId: 'read-only-policy' }),
    error => error.code === 'DSH_POLICY_TOO_NARROW',
  )
})

test('superseded plans cannot execute correction or acceptance', async () => {
  const { core, workspace, dsh } = await makeCore()
  const plan = await approvedPlan(core, workspace, { planId: 'superseded-plan' })
  const started = await core.startTask({ planId: plan.planId, version: plan.version, taskId: 'superseded-task' })
  await waitFor(async () => {
    const current = await core.getTask(started.id)
    return current.status === 'waiting_review' && current.evidenceIds.some(id => core.store.state.evidence[id]?.kind === 'task.event_log')
  })

  const revised = await core.submitPlan({
    planId: plan.planId,
    objective: 'revised objective',
    scope: { workspace, allowedPaths: [workspace], operations: ['read'] },
    constraints: [],
    acceptanceCriteria: [{ id: 'c1', description: 'a verifiable result' }],
    executionPrompt: 'perform the revised test task',
  })
  const requested = await core.requestPlanApproval({ planId: revised.planId, version: revised.version })
  await core.decideHumanApproval(requested.approval.id, 'approve')

  await assert.rejects(
    core.sendCorrection({ taskId: started.id, correction: 'continue the old plan' }),
    error => error.code === 'PLAN_NOT_CURRENTLY_APPROVED',
  )
  const current = await core.getTask(started.id)
  const evidence = current.evidenceIds.find(id => core.store.state.evidence[id]?.kind === 'workspace.after')
  await assert.rejects(
    core.recordAcceptance({ taskId: started.id, criteria: [{ id: 'c1', result: 'pass', evidenceIds: [evidence] }] }),
    error => error.code === 'PLAN_NOT_CURRENTLY_APPROVED',
  )
  assert.equal(dsh.promptCalls.length, 1)
})

test('cancelling a waiting-review task completes without a DSH cancel call', async () => {
  const { core, workspace, dsh } = await makeCore()
  const plan = await approvedPlan(core, workspace)
  const started = await core.startTask({ planId: plan.planId, version: plan.version, taskId: 'static-cancel' })
  await waitFor(async () => {
    const current = await core.getTask(started.id)
    return current.status === 'waiting_review' && current.evidenceIds.some(id => core.store.state.evidence[id]?.kind === 'task.event_log')
  })

  const cancelled = await core.cancelTask(started.id)
  assert.equal(cancelled.status, 'cancelled')
  assert.deepEqual(dsh.cancelCalls, [])
})

test('workspace before evidence belongs to the current run and can be accepted', async () => {
  const { core, workspace } = await makeCore()
  const plan = await approvedPlan(core, workspace, { evidenceKinds: ['workspace.before', 'workspace.after'] })
  const started = await core.startTask({ planId: plan.planId, version: plan.version, taskId: 'before-run-evidence' })
  await waitFor(async () => {
    const current = await core.getTask(started.id)
    const kinds = new Set(current.evidenceIds.map(id => core.store.state.evidence[id]?.kind))
    return current.status === 'waiting_review' && kinds.has('workspace.before') && kinds.has('workspace.after')
  })

  const task = await core.getTask(started.id)
  const before = task.evidenceIds.map(id => core.store.state.evidence[id]).find(item => item.kind === 'workspace.before')
  const after = task.evidenceIds.map(id => core.store.state.evidence[id]).find(item => item.kind === 'workspace.after')
  assert.equal(before.executionRunId, task.executionRunId)
  assert.equal(after.executionRunId, task.executionRunId)
  const accepted = await core.recordAcceptance({
    taskId: task.id,
    criteria: [{ id: 'c1', result: 'pass', evidenceIds: [before.id, after.id] }],
  })
  assert.equal(accepted.status, 'accepted')
})

test('all ACP updates are persisted as evidence when display events are truncated', async () => {
  const { core, workspace, dsh } = await makeCore({ maxTaskEvents: 20 })
  const promptGate = deferred()
  dsh.promptGate = promptGate
  const plan = await approvedPlan(core, workspace)
  const started = await core.startTask({ planId: plan.planId, version: plan.version, taskId: 'complete-events' })
  await waitFor(async () => {
    const current = await core.getTask(started.id)
    return current.status === 'running' && current.dshSessionId === 'session-1'
  })

  for (let sequence = 1; sequence <= 25; sequence += 1) {
    dsh.emit('update', {
      sequence,
      at: new Date().toISOString(),
      sessionId: 'session-1',
      update: {
        sessionUpdate: 'tool_call',
        toolCallId: `call-${sequence}`,
        title: `tool-${sequence}`,
        kind: 'other',
        rawInput: { file_path: 'inside.txt' },
      },
    })
  }
  await waitFor(async () => Object.values(core.store.state.evidence).filter(item => item.taskId === started.id && item.kind === 'dsh.session_update').length === 25)
  const task = await core.getTask(started.id)
  const updates = Object.values(core.store.state.evidence)
    .filter(item => item.taskId === started.id && item.kind === 'dsh.session_update')
    .sort((left, right) => left.content.sequence - right.content.sequence)
  assert.equal(updates.length, 25)
  assert.equal(updates[0].content.sequence, 1)
  assert.ok(task.events.length <= 20)

  promptGate.resolve(dsh.promptResult)
  await waitFor(async () => {
    const current = await core.getTask(started.id)
    return current.status === 'waiting_review' && current.evidenceIds.some(id => core.store.state.evidence[id]?.kind === 'task.event_log')
  })
})

test('unknown ACP permission tool shapes are denied instead of treated as execute', async () => {
  const { core, workspace, dsh, store } = await makeCore()
  const plan = await approvedPlan(core, workspace, { operations: ['execute'] })
  store.state.tasks['permission-test'] = {
    id: 'permission-test',
    planId: plan.planId,
    planVersion: plan.version,
    planHash: plan.hash,
    workspace,
    allowedPaths: [workspace],
    executionCwd: workspace,
    status: 'waiting_permission',
    dshSessionId: 'permission-session',
    pendingPermissionId: 'permission-1',
    pendingPermission: {
      permissionId: 'permission-1',
      sessionId: 'permission-session',
      toolCall: { toolCallId: 'call-1', kind: 'other', name: '', title: '' },
    },
    events: [],
    evidenceIds: [],
    eventSeq: 0,
  }
  await assert.rejects(
    core.decidePermission({ taskId: 'permission-test', permissionId: 'permission-1', allow: true, optionId: 'allow-once' }),
    error => error.code === 'UNKNOWN_TOOL_SHAPE',
  )
  assert.deepEqual(dsh.permissionDecisions, [{ permissionId: 'permission-1', allow: false }])
})
