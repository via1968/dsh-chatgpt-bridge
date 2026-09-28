import { createHash } from 'node:crypto'
import { execFile } from 'node:child_process'
import { access, lstat, readFile, realpath } from 'node:fs/promises'
import { constants } from 'node:fs'
import { basename, dirname, isAbsolute, join, relative, resolve, sep } from 'node:path'
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

/**
 * Resolve a tool-supplied path from the DSH session cwd and account for
 * symlinked parents even when the final path does not exist yet.
 */
export async function resolvePathForScope(value, baseDirectory) {
  if (typeof value !== 'string' || value.trim() === '') throw new Error('tool path must be a non-empty string')
  const lexical = resolve(baseDirectory, value)
  let cursor = lexical
  const missing = []
  while (true) {
    try {
      const physical = await realpath(cursor)
      return missing.reverse().reduce((current, segment) => join(current, segment), physical)
    } catch (error) {
      if (error?.code !== 'ENOENT') throw error
      const parent = dirname(cursor)
      if (parent === cursor) return lexical
      missing.push(basename(cursor))
      cursor = parent
    }
  }
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

function decodeGitQuotedToken(token) {
  if (!token.startsWith('"') || !token.endsWith('"')) return token
  const raw = token.slice(1, -1)
  const bytes = []
  for (let index = 0; index < raw.length;) {
    if (raw[index] !== '\\') {
      const codePoint = raw.codePointAt(index)
      const character = String.fromCodePoint(codePoint)
      bytes.push(...Buffer.from(character, 'utf8'))
      index += character.length
      continue
    }
    index += 1
    if (index >= raw.length) {
      bytes.push('\\'.charCodeAt(0))
      break
    }
    if (/[0-7]/.test(raw[index])) {
      let digits = raw[index]
      index += 1
      while (digits.length < 3 && index < raw.length && /[0-7]/.test(raw[index])) digits += raw[index++]
      bytes.push(Number.parseInt(digits, 8))
      continue
    }
    const escapes = { a: 7, b: 8, t: 9, n: 10, v: 11, f: 12, r: 13 }
    bytes.push(escapes[raw[index]] ?? raw.charCodeAt(index))
    index += 1
  }
  return Buffer.from(bytes).toString('utf8')
}

function parseGitToken(value, start) {
  let index = start
  while (index < value.length && /\s/.test(value[index])) index += 1
  if (index >= value.length) return undefined
  if (value[index] !== '"') {
    const begin = index
    while (index < value.length && !/\s/.test(value[index])) index += 1
    return { token: value.slice(begin, index), next: index }
  }
  const begin = index
  index += 1
  while (index < value.length) {
    if (value[index] === '\\') {
      index += 1
      if (index >= value.length) break
      if (/[0-7]/.test(value[index])) {
        let digits = 0
        while (index < value.length && digits < 3 && /[0-7]/.test(value[index])) {
          index += 1
          digits += 1
        }
      } else {
        index += 1
      }
      continue
    }
    if (value[index] === '"') {
      index += 1
      return { token: decodeGitQuotedToken(value.slice(begin, index)), next: index }
    }
    index += 1
  }
  return undefined
}

function parseGitDiffHeader(line) {
  const prefix = 'diff --git '
  if (!line.startsWith(prefix)) return undefined
  const left = parseGitToken(line, prefix.length)
  if (left === undefined) return undefined
  const right = parseGitToken(line, left.next)
  if (right === undefined) return undefined
  return [left.token, right.token]
}

function parseGitNameOnlyZ(value) {
  return String(value ?? '').split('\0').filter(Boolean)
}

// The diff header is presentation text, not a reliable path serialization:
// unquoted spaces are legal and quoted paths use Git's C-style escaping. Use
// the NUL-delimited path list as the source of truth and only use the header
// to associate a rendered diff block with one of those exact paths.
function headerReferencesGitPath(line, path) {
  const normalized = String(path).replaceAll('\\', '/')
  const candidates = [`a/${normalized}`, `b/${normalized}`]
  const parsed = parseGitDiffHeader(line)
  if (parsed?.some(token => candidates.includes(token))) return true

  for (const candidate of candidates) {
    let offset = line.indexOf(candidate, 'diff --git '.length)
    while (offset !== -1) {
      const previous = offset === 'diff --git '.length ? undefined : line[offset - 1]
      const next = line[offset + candidate.length]
      const startsPath = previous === undefined || /\s/.test(previous) || previous === '"'
      const endsPath = next === undefined || /\s/.test(next) || next === '"'
      if (startsPath && endsPath) return true
      offset = line.indexOf(candidate, offset + 1)
    }
  }
  return false
}

function redactGitDiff(value, changedPaths) {
  const paths = changedPaths?.map(path => String(path).replaceAll('\\', '/'))
  let sensitive = false
  const output = []
  for (const line of String(value ?? '').split(/\r?\n/)) {
    if (line.startsWith('diff --git ')) {
      if (paths === undefined) {
        sensitive = true
      } else {
        const matchingPaths = paths.filter(path => headerReferencesGitPath(line, path))
        sensitive = matchingPaths.length === 0 || matchingPaths.some(path => sensitivePath(path))
      }
      output.push(redactText(line))
      if (sensitive) output.push('[REDACTED SENSITIVE FILE DIFF]')
      continue
    }
    if (sensitive) continue
    output.push(redactText(line))
  }
  return output.join('\n')
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

async function runGitDiffWithPaths(diffArgs, pathspecs, cwd) {
  const namesArgs = [diffArgs[0], '--no-renames', '--name-only', '-z', ...diffArgs.slice(1)]
  const [diff, names] = await Promise.all([
    runGit(scopedGitArgs(diffArgs, pathspecs), cwd),
    runGit(scopedGitArgs(namesArgs, pathspecs), cwd),
  ])
  return {
    diff,
    changedPaths: names.ok ? parseGitNameOnlyZ(names.stdout) : undefined,
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
  const [status, diffResult, cachedDiffResult, head, branch] = await Promise.all([
    runGit(scopedGitArgs(['status', '--short', '--branch'], pathspecs), gitCwd),
    runGitDiffWithPaths(['diff', '--binary'], pathspecs, gitCwd),
    runGitDiffWithPaths(['diff', '--cached', '--binary'], pathspecs, gitCwd),
    runGit(['rev-parse', 'HEAD'], gitCwd),
    runGit(['symbolic-ref', '--short', '-q', 'HEAD'], gitCwd),
  ])
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
      diff: trimOutput(redactGitDiff(diffResult.diff.stdout || diffResult.diff.stderr, diffResult.changedPaths), limits.evidenceBytes),
      cachedDiff: trimOutput(redactGitDiff(cachedDiffResult.diff.stdout || cachedDiffResult.diff.stderr, cachedDiffResult.changedPaths), limits.evidenceBytes),
      untracked,
    },
  }
}

export async function captureWorkspaceDelta(before, after, limits) {
  const committed = { ok: false, stdout: '', stderr: 'No comparable Git HEADs were captured.' }
  let committedPaths
  if (before?.git?.head !== undefined && after?.git?.head !== undefined && before.gitRoot !== undefined && before.gitRoot === after.gitRoot) {
    const committedResult = await runGitDiffWithPaths(
      ['diff', '--binary', before.git.head, after.git.head],
      after.pathspecs ?? [],
      after.gitRoot ?? after.workspace,
    )
    Object.assign(committed, committedResult.diff)
    committedPaths = committedResult.changedPaths
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
    committedDuringExecution: trimOutput(redactGitDiff(committed.stdout || committed.stderr, committedPaths), limits.evidenceBytes),
    committedDiffComparable: committed.ok,
  }
}
