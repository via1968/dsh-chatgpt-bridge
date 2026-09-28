import { mkdtemp, rm } from 'node:fs/promises'
import { tmpdir } from 'node:os'
import { join } from 'node:path'
import { DshAcpManager } from '../src/dsh-acp.mjs'

const cwd = await mkdtemp(join(tmpdir(), 'dsh-chatgpt-bridge-smoke-'))
const extraEnv = {
  ...(process.env.DEEPSEEK_API_KEY === undefined ? { DEEPSEEK_API_KEY: 'sk-dummy-for-boot' } : {}),
  ...(process.env.DSH_PERMISSION_MODE === undefined ? { DSH_PERMISSION_MODE: 'read-only' } : {}),
}
const manager = new DshAcpManager({
  command: process.env.DSH_COMMAND ?? (process.platform === 'win32' ? 'dsh.cmd' : 'dsh'),
  args: ['--profile', process.env.DSH_PROFILE ?? 'acp'],
  launchCwd: cwd,
  extraEnv,
  permissionTimeoutMs: 30000,
})

try {
  await manager.ensureConnected()
  const sessionId = await manager.createSession(cwd)
  console.log(JSON.stringify({ ok: true, sessionId, status: manager.status() }, null, 2))
} finally {
  await manager.close()
  await rm(cwd, { recursive: true, force: true })
}
