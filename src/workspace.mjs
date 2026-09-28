import { createHash } from 'node:crypto'
import { execFile } from 'node:child_process'
import { access, lstat, readFile, realpath } from 'node:fs/promises'
import { constants } from 'node:fs'
import { isAbsolute, relative, resolve, sep } from 'node:path'
import { promisify } from 'node:util'

const execFileAsync = promisify(execFile)

export function normalizeAbsolutePath(value, label) {
  if (typeof value !== 'string' || value.trim() === '') throw new Error(`${label} must be a non-empty path`)
  const candidate = resolve(value)
  if (!isAbsolute(candidate)) throw new Error(`${label} must be absolute`)
  return candidate
}

export function isPathWithin(root, candidate) {
  const rootResolved = resolve(root)
  const candidateResolved = resolve(candidate)
  if (rootResolved === candidateResolved) return true
  const child = relative(rootResolved, candidateResolved)
  return child !== '' && !child.startsWith(`..${sep}`) && child !== '..' && !isAbsolute(child)
}

export async function assertDirectory(path, label) {
  const normalized = normalizeAbsolutePath(path, label)
  const physical = await realpath(normalized)
  const info = await lstat(physical)
  if (!info.isDirectory()) throw new Error(`${label} is not a directory: ${physical}`)
  await access(physical, constants.R_OK | constants.X_OK)
  return physical
}

export function assertWorkspaceAllowed(workspace, configuredRoot) {
  const normalized = normalizeAbsolutePath(workspace, 'scope.workspace')
  if (configuredRoot !== undefined && !isPathWithin(configuredRoot, normalized)) {
    throw new Error(`scope.workspace is outside BRIDGE_WORKSPACE_ROOT: ${normalized}`)
  }
  return normalized
}

export async function assertPathListAllowed(paths, workspace, configuredRoot) {
  if (!Array.isArray(paths) || paths.length === 0) throw new Error('scope.allowedPaths must contain at least one path')
  const result = []
  let physicalConfiguredRoot = configuredRoot
  if (configuredRoot !== undefined) {
    try { physicalConfiguredRoot = await realpath(configuredRoot) } catch (error) {
      if (error?.code !== 'ENOENT') throw error
    }
  }
  for (const [index, value] of paths.entries()) {
    const normalized = normalizeAbsolutePath(value, `scope.allowedPaths[${index}]`)
    let candidate = normalized
    try {
      candidate = await realpath(normalized)
    } catch (error) {
      if (error?.code !== 'ENOENT') throw error
    }
    if (!isPathWithin(workspace, candidate)) throw new Error(`scope.allowedPaths[${index}] is outside scope.workspace`)
    if (physicalConfiguredRoot !== undefined && !isPathWithin(physicalConfiguredRoot, candidate)) {
      throw new Error(`scope.allowedPaths[${index}] is outside BRIDGE_WORKSPACE_ROOT`)
    }
    if (!result.includes(candidate)) result.push(candidate)
  }
  return result
}

const SENSITIVE_PATH = /(^|[\\/])(?:\.env(?:\..*)?|.*\.(?:pem|key|p12|pfx|jks|der)|id_(?:rsa|dsa|ecdsa|ed25519)|.*(?:credential|secret|token|password).*|credentials?(?:\..*)?|secrets?(?:\..*)?)$/i

function redactText(value) {
  return String(value ?? '')
    .replace(/(Bearer\s+)[A-Za-z0-9._~+/=-]+/gi, '$1[REDACTED]')
    .replace(/(sk-[A-Za-z0-9_-]{12,})/g, '[REDACTED_API_KEY]')
    .replace(/((?:api[_-]?key|access[_-]?token|refresh[_-]?token|token|secret|password|authorization|private[_-]?key)\s*[=:]\s*)(["']?)[^\s"',;]+/gi, '$1$2[REDACTED]')
}

function sensitivePath(path) {
  return SENSITIVE_PATH.test(path)
}

function redactGitDiff(value) {
  let sensitive = false
  return String(value ?? '').split(/\r?\n/).map(line => {
    const header = /^diff --git a\/(.+) b\/(.+)$/.exec(line)
    if (header !== null) sensitive = sensitivePath(header[1]) || sensitivePath(header[2])
    if (sensitive && (/^[+-]/.test(line) && !line.startsWith('+++') && !line.startsWith('---'))) {
      return `${line[0]}[REDACTED SENSITIVE FILE DIFF]`
    }
    return redactText(line)
  }).join('\n')
}

function trimOutput(value, maxBytes) {
  const text = String(value ?? '')
  const bytes = Buffer.byteLength(text, 'utf8')
  if (bytes <= maxBytes) return { text, truncated: false, bytes }
  let end = Math.min(text.length, maxBytes)
  while (end > 0 && Buffer.byteLength(text.slice(0, end), 'utf8') > maxBytes) end -= 1
  return { text: `${text.slice(0, end)}\n[truncated: ${bytes} bytes total]`, truncated: true, bytes }
}

async function runGit(args, cwd) {
  try {
    const result = await execFileAsync('git', ['--no-optional-locks', ...args], {
      cwd,
      windowsHide: true,
      maxBuffer: 16 * 1024 * 1024,
      encoding: 'utf8',
    })
    return { ok: true, exitCode: 0, stdout: result.stdout, stderr: result.stderr }
  } catch (error) {
    return {
      ok: false,
      exitCode: typeof error?.code === 'number' ? error.code : 1,
      stdout: error?.stdout ?? '',
      stderr: error?.stderr ?? String(error?.message ?? error),
    }
  }
}

async function hashAndMaybeRead(path, relativePath, maxBytes) {
  const bytes = await readFile(path)
  const sourceSha256 = createHash('sha256').update(bytes).digest('hex')
  if (sensitivePath(relativePath)) {
    const redactedContent = '[REDACTED SENSITIVE FILE]'
    return {
      size: bytes.length,
      sha256: sourceSha256,
      contentSha256: createHash('sha256').update(redactedContent).digest('hex'),
      content: undefined,
      truncated: false,
      redacted: true,
      redaction: 'sensitive-file',
    }
  }
  if (bytes.length > maxBytes) {
    return { size: bytes.length, sha256: sourceSha256, content: undefined, truncated: true, redacted: false }
  }
  const rawContent = bytes.includes(0) ? undefined : bytes.toString('utf8')
  const content = rawContent === undefined ? undefined : redactText(rawContent)
  return {
    size: bytes.length,
    sha256: sourceSha256,
    ...(content === undefined ? {} : { contentSha256: createHash('sha256').update(content).digest('hex') }),
    content,
    truncated: false,
    binary: content === undefined,
    redacted: content !== rawContent,
  }
}

async function pathspecsForGit(gitRoot, allowedPaths) {
  if (gitRoot === undefined) return []
  const physicalGitRoot = await realpath(gitRoot)
  return Promise.all(allowedPaths.map(async path => {
    let physicalPath = path
    try { physicalPath = await realpath(path) } catch (error) {
      if (error?.code !== 'ENOENT') throw error
    }
    if (!isPathWithin(physicalGitRoot, physicalPath)) throw new Error(`scope path is outside git root: ${path}`)
    const value = relative(physicalGitRoot, physicalPath).split(sep).join('/')
    return value === '' ? '.' : value
  }))
}

function scopedGitArgs(args, pathspecs) {
  return pathspecs.length === 0 ? args : [...args, '--', ...pathspecs]
}

async function collectUntracked(gitRoot, workspace, pathspecs, maxBytes) {
  const result = await runGit(scopedGitArgs(['ls-files', '--others', '--exclude-standard', '-z'], pathspecs), gitRoot)
  if (!result.ok) return []
  const names = result.stdout.split('\0').filter(Boolean)
  const files = []
  for (const name of names) {
    const path = resolve(gitRoot, name)
    if (!isPathWithin(workspace, path)) continue
    const displayPath = relative(workspace, path).split(sep).join('/') || name
    try {
      const physical = await realpath(path)
      if (!isPathWithin(workspace, physical)) {
        files.push({ path: displayPath, unavailable: 'symlink resolves outside workspace' })
        continue
      }
      const file = await hashAndMaybeRead(physical, displayPath, maxBytes)
      files.push({ path: displayPath, ...file })
    } catch (error) {
      files.push({ path: displayPath, unavailable: String(error?.message ?? error) })
    }
  }
  return files
}

/**
 * Capture read-only workspace facts. The bridge never writes project files and
 * never executes a user-supplied command here; DSH remains the executor.
 */
export async function captureWorkspaceSnapshot(workspace, limits, { allowedPaths = [workspace] } = {}) {
  const normalized = await assertDirectory(workspace, 'workspace')
  const root = await runGit(['rev-parse', '--show-toplevel'], normalized)
  const gitRoot = root.ok ? root.stdout.trim() : undefined
  const canonicalAllowedPaths = await Promise.all(allowedPaths.map(async path => {
    try { return await realpath(path) } catch (error) {
      if (error?.code !== 'ENOENT') throw error
      return path
    }
  }))
  const pathspecs = await pathspecsForGit(gitRoot, canonicalAllowedPaths)
  const gitCwd = gitRoot ?? normalized
  const status = await runGit(scopedGitArgs(['status', '--short', '--branch'], pathspecs), gitCwd)
  const diff = await runGit(scopedGitArgs(['diff', '--binary'], pathspecs), gitCwd)
  const cachedDiff = await runGit(scopedGitArgs(['diff', '--cached', '--binary'], pathspecs), gitCwd)
  const head = await runGit(['rev-parse', 'HEAD'], gitCwd)
  const branch = await runGit(['symbolic-ref', '--short', '-q', 'HEAD'], gitCwd)
  const untracked = gitRoot === undefined ? [] : await collectUntracked(await realpath(gitRoot), normalized, pathspecs, limits.untrackedFileBytes)
  return {
    capturedAt: new Date().toISOString(),
    workspace: normalized,
    gitRoot,
    allowedPaths: canonicalAllowedPaths,
    pathspecs,
    git: {
      available: root.ok,
      head: head.ok ? head.stdout.trim() : undefined,
      branch: branch.ok ? branch.stdout.trim() : undefined,
      status: trimOutput(status.stdout || status.stderr, limits.evidenceBytes),
      diff: trimOutput(redactGitDiff(diff.stdout || diff.stderr), limits.evidenceBytes),
      cachedDiff: trimOutput(redactGitDiff(cachedDiff.stdout || cachedDiff.stderr), limits.evidenceBytes),
      untracked,
    },
  }
}

export async function captureWorkspaceDelta(before, after, limits) {
  const committed = { ok: false, stdout: '', stderr: 'No comparable Git HEADs were captured.' }
  if (before?.git?.head !== undefined && after?.git?.head !== undefined && before.gitRoot !== undefined && before.gitRoot === after.gitRoot) {
    Object.assign(committed, await runGit(
      scopedGitArgs(['diff', '--binary', before.git.head, after.git.head], after.pathspecs ?? []),
      after.gitRoot ?? after.workspace,
    ))
  }
  return {
    workspace: after?.workspace,
    allowedPaths: after?.allowedPaths,
    pathspecs: after?.pathspecs,
    before: {
      capturedAt: before?.capturedAt,
      head: before?.git?.head,
      branch: before?.git?.branch,
      status: before?.git?.status,
      diff: before?.git?.diff,
      cachedDiff: before?.git?.cachedDiff,
      untracked: before?.git?.untracked,
    },
    after: {
      capturedAt: after?.capturedAt,
      head: after?.git?.head,
      branch: after?.git?.branch,
      status: after?.git?.status,
      diff: after?.git?.diff,
      cachedDiff: after?.git?.cachedDiff,
      untracked: after?.git?.untracked,
    },
    committedDuringExecution: trimOutput(redactGitDiff(committed.stdout || committed.stderr), limits.evidenceBytes),
    committedDiffComparable: committed.ok,
  }
}
