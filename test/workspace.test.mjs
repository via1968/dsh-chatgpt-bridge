import test, { afterEach } from 'node:test'
import assert from 'node:assert/strict'
import { execFile } from 'node:child_process'
import { mkdir, mkdtemp, readFile, rm, writeFile } from 'node:fs/promises'
import { tmpdir } from 'node:os'
import { join, relative } from 'node:path'
import { promisify } from 'node:util'
import { captureWorkspaceDelta, captureWorkspaceSnapshot } from '../src/workspace.mjs'

const execFileAsync = promisify(execFile)
const temporaryRoots = []
const limits = {
  evidenceBytes: 512 * 1024,
  untrackedFileBytes: 512 * 1024,
}

async function git(cwd, ...args) {
  return execFileAsync('git', ['--no-optional-locks', ...args], { cwd, encoding: 'utf8', windowsHide: true })
}

async function makeRepo() {
  const root = await mkdtemp(join(tmpdir(), 'dsh-bridge-workspace-'))
  temporaryRoots.push(root)
  const allowed = join(root, 'allowed')
  await mkdir(allowed)
  await writeFile(join(allowed, 'tracked.txt'), 'before\n')
  await writeFile(join(root, 'outside.txt'), 'outside-before\n')
  await git(root, 'init', '-b', 'main')
  await git(root, 'config', 'user.email', 'bridge-test@example.invalid')
  await git(root, 'config', 'user.name', 'bridge test')
  await git(root, 'add', '.')
  await git(root, 'commit', '-m', 'baseline')
  return { root, allowed }
}

afterEach(async () => {
  while (temporaryRoots.length > 0) await rm(temporaryRoots.pop(), { recursive: true, force: true })
})

test('Git status and diff are restricted to the approved pathspec', async () => {
  const { root, allowed } = await makeRepo()
  await writeFile(join(allowed, 'tracked.txt'), 'allowed-after\n')
  await writeFile(join(root, 'outside.txt'), 'outside-after\n')
  const snapshot = await captureWorkspaceSnapshot(root, limits, { allowedPaths: [allowed] })
  assert.match(snapshot.git.diff.text, /allowed-after/)
  assert.doesNotMatch(snapshot.git.diff.text, /outside-after/)
  assert.deepEqual(snapshot.pathspecs, ['allowed'])
})

test('sensitive untracked files are not returned as plaintext', async () => {
  const { root, allowed } = await makeRepo()
  const secret = 'DEEPSEEK_API_KEY=synthetic-secret-value\nPASSWORD=another-secret\n'
  await writeFile(join(allowed, 'bridge-notes.txt'), secret)
  const snapshot = await captureWorkspaceSnapshot(root, limits, { allowedPaths: [allowed] })
  const env = snapshot.git.untracked.find(item => item.path === 'allowed/bridge-notes.txt')
  assert.ok(env)
  assert.ok(env.content)
  assert.equal(env.redacted, true)
  assert.doesNotMatch(env.content, /synthetic-secret-value/)
  assert.doesNotMatch(env.content, /another-secret/)
})

test('sensitive tracked diff context is redacted as a whole file block', async () => {
  const { root, allowed } = await makeRepo()
  const envPath = join(allowed, '.env')
  await writeFile(envPath, 'CUSTOM_VALUE=synthetic-review-sensitive\n# baseline comment\n')
  await git(root, 'add', '-f', join(relative(root, allowed), '.env'))
  await git(root, 'commit', '-m', 'add sensitive file')
  await writeFile(envPath, 'CUSTOM_VALUE=synthetic-review-sensitive\n# changed comment\n')

  const snapshot = await captureWorkspaceSnapshot(root, limits, { allowedPaths: [allowed] })
  assert.match(snapshot.git.diff.text, /diff --git a\/allowed\/.env b\/allowed\/.env/)
  assert.match(snapshot.git.diff.text, /REDACTED SENSITIVE FILE DIFF/)
  assert.doesNotMatch(snapshot.git.diff.text, /synthetic-review-sensitive/)
  assert.doesNotMatch(snapshot.git.diff.text, /baseline comment|changed comment/)
})

test('sensitive diff blocks with Git-quoted Unicode paths are redacted', async () => {
  const { root, allowed } = await makeRepo()
  const chineseDirectory = join(allowed, '中文目录')
  await mkdir(chineseDirectory)
  await git(root, 'config', 'core.quotePath', 'true')
  const envPath = join(chineseDirectory, '.env')
  await writeFile(envPath, 'CUSTOM_VALUE=synthetic-unicode-review-secret\n# baseline comment\n')
  await git(root, 'add', '-f', join(relative(root, chineseDirectory), '.env'))
  await git(root, 'commit', '-m', 'add Unicode sensitive file')
  await writeFile(envPath, 'CUSTOM_VALUE=synthetic-unicode-review-secret\n# changed comment\n')

  const snapshot = await captureWorkspaceSnapshot(root, limits, { allowedPaths: [allowed] })
  assert.match(snapshot.git.diff.text, /REDACTED SENSITIVE FILE DIFF/)
  assert.doesNotMatch(snapshot.git.diff.text, /synthetic-unicode-review-secret/)
  assert.doesNotMatch(snapshot.git.diff.text, /baseline comment|changed comment/)
})

test('workspace delta records committed changes between HEADs', async () => {
  const { root, allowed } = await makeRepo()
  const before = await captureWorkspaceSnapshot(root, limits, { allowedPaths: [allowed] })
  await writeFile(join(allowed, 'tracked.txt'), 'committed-after\n')
  await git(root, 'add', join(relative(root, allowed), 'tracked.txt'))
  await git(root, 'commit', '-m', 'execution commit')
  const after = await captureWorkspaceSnapshot(root, limits, { allowedPaths: [allowed] })
  const delta = await captureWorkspaceDelta(before, after, limits)
  assert.equal(delta.committedDiffComparable, true)
  assert.notEqual(delta.before.head, delta.after.head)
  assert.match(delta.committedDuringExecution.text, /committed-after/)
})
