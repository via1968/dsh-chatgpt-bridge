import { createHash, randomUUID } from 'node:crypto'
import { mkdir, readFile, rename, writeFile } from 'node:fs/promises'
import { dirname, join } from 'node:path'

const EMPTY_STATE = () => ({
  schemaVersion: 1,
  plans: {},
  approvals: {},
  tasks: {},
  evidence: {},
})

function isRecord(value) {
  return value !== null && typeof value === 'object' && !Array.isArray(value)
}

function mergeState(value) {
  const base = EMPTY_STATE()
  if (!isRecord(value)) return base
  for (const key of Object.keys(base)) {
    if (key === 'schemaVersion') continue
    if (isRecord(value[key])) base[key] = value[key]
  }
  base.schemaVersion = Number.isInteger(value.schemaVersion) ? value.schemaVersion : 1
  return base
}

/** Stable JSON for plan hashes and audit comparisons. */
export function stableStringify(value) {
  if (value === null || typeof value !== 'object') return JSON.stringify(value)
  if (Array.isArray(value)) return `[${value.map(stableStringify).join(',')}]`
  const entries = Object.entries(value)
    .filter(([, item]) => item !== undefined)
    .sort(([left], [right]) => left.localeCompare(right))
  return `{${entries.map(([key, item]) => `${JSON.stringify(key)}:${stableStringify(item)}`).join(',')}}`
}

export function sha256(value) {
  return createHash('sha256').update(typeof value === 'string' ? value : stableStringify(value)).digest('hex')
}

export function newId(prefix) {
  return `${prefix}_${randomUUID()}`
}

export function clone(value) {
  return value === undefined ? undefined : JSON.parse(JSON.stringify(value))
}

export class JsonStore {
  constructor(filePath) {
    this.filePath = filePath
    this.state = EMPTY_STATE()
    this.writeChain = Promise.resolve()
  }

  async open() {
    await mkdir(dirname(this.filePath), { recursive: true })
    try {
      const raw = await readFile(this.filePath, 'utf8')
      this.state = mergeState(JSON.parse(raw))
    } catch (error) {
      if (error?.code !== 'ENOENT') throw error
      this.state = EMPTY_STATE()
      await this.flush()
    }
    return this
  }

  snapshot() {
    return clone(this.state)
  }

  async mutate(mutator) {
    const operation = this.writeChain.then(async () => {
      const result = await mutator(this.state)
      await this.flush()
      return result
    })
    this.writeChain = operation.catch(() => {})
    return operation
  }

  async flush() {
    const temporary = join(dirname(this.filePath), `.${this.filePath.split(/[\\/]/).pop()}.${randomUUID()}.tmp`)
    await writeFile(temporary, `${JSON.stringify(this.state, null, 2)}\n`, { encoding: 'utf8', mode: 0o600 })
    await rename(temporary, this.filePath)
  }
}
