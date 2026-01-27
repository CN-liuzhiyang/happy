/**
 * Session state persistence for happy CLI
 *
 * Allows resuming sessions after CLI restart by persisting:
 * - Claude session ID (for --resume)
 * - Server session ID (for reconnection)
 * - Encryption keys (for server communication)
 */

import { readFile, writeFile, mkdir, open, unlink, rename, stat } from 'node:fs/promises'
import { existsSync } from 'node:fs'
import { constants } from 'node:fs'
import { configuration } from '@/configuration'
import { logger } from '@/ui/logger'
import * as z from 'zod'

// Schema version for migrations
const CURRENT_SCHEMA_VERSION = 1

// Session expiry (24 hours)
const SESSION_EXPIRY_MS = 24 * 60 * 60 * 1000

// Saved session schema
const SavedSessionSchema = z.object({
  claudeSessionId: z.string(),
  serverSessionId: z.string(),
  serverSessionTag: z.string(),
  encryptionKey: z.string(), // Base64
  encryptionVariant: z.enum(['legacy', 'dataKey']),
  workingDirectory: z.string(),
  lastActiveAt: z.number(),
  metadataVersion: z.number(),
  agentStateVersion: z.number(),
})

export type SavedSession = z.infer<typeof SavedSessionSchema>

const SessionStateSchema = z.object({
  schemaVersion: z.number(),
  sessions: z.record(SavedSessionSchema),
  lastActiveWorkingDirectory: z.string().optional(),
})

export type SessionState = z.infer<typeof SessionStateSchema>

const defaultState: SessionState = {
  schemaVersion: CURRENT_SCHEMA_VERSION,
  sessions: {},
}

/**
 * Check if a session is expired
 */
export function isSessionExpired(session: SavedSession): boolean {
  return Date.now() - session.lastActiveAt > SESSION_EXPIRY_MS
}

/**
 * Format time ago for display
 */
export function formatTimeAgo(timestamp: number): string {
  const seconds = Math.floor((Date.now() - timestamp) / 1000)

  if (seconds < 60) return 'just now'
  if (seconds < 3600) {
    const minutes = Math.floor(seconds / 60)
    return `${minutes} minute${minutes === 1 ? '' : 's'} ago`
  }
  if (seconds < 86400) {
    const hours = Math.floor(seconds / 3600)
    return `${hours} hour${hours === 1 ? '' : 's'} ago`
  }
  const days = Math.floor(seconds / 86400)
  return `${days} day${days === 1 ? '' : 's'} ago`
}

/**
 * Read session state from file
 */
export async function readSessionState(): Promise<SessionState> {
  if (!existsSync(configuration.sessionStateFile)) {
    return { ...defaultState }
  }

  try {
    const content = await readFile(configuration.sessionStateFile, 'utf8')
    const raw = JSON.parse(content)
    return SessionStateSchema.parse(raw)
  } catch (error: any) {
    logger.warn(`Failed to read session state: ${error.message}`)
    return { ...defaultState }
  }
}

/**
 * Atomically update session state with file locking
 */
export async function updateSessionState(
  updater: (current: SessionState) => SessionState | Promise<SessionState>
): Promise<SessionState> {
  // Timing constants
  const LOCK_RETRY_INTERVAL_MS = 100
  const MAX_LOCK_ATTEMPTS = 50
  const STALE_LOCK_TIMEOUT_MS = 10000

  const lockFile = configuration.sessionStateFile + '.lock'
  const tmpFile = configuration.sessionStateFile + '.tmp'
  let fileHandle
  let attempts = 0

  // Acquire exclusive lock with retries
  while (attempts < MAX_LOCK_ATTEMPTS) {
    try {
      fileHandle = await open(lockFile, constants.O_CREAT | constants.O_EXCL | constants.O_WRONLY)
      break
    } catch (err: any) {
      if (err.code === 'EEXIST') {
        attempts++
        await new Promise(resolve => setTimeout(resolve, LOCK_RETRY_INTERVAL_MS))

        // Check for stale lock
        try {
          const stats = await stat(lockFile)
          if (Date.now() - stats.mtimeMs > STALE_LOCK_TIMEOUT_MS) {
            await unlink(lockFile).catch(() => { })
          }
        } catch { }
      } else {
        throw err
      }
    }
  }

  if (!fileHandle) {
    throw new Error(`Failed to acquire session state lock after ${MAX_LOCK_ATTEMPTS * LOCK_RETRY_INTERVAL_MS / 1000} seconds`)
  }

  try {
    // Read current state
    const current = await readSessionState()

    // Apply update
    const updated = await updater(current)

    // Ensure directory exists
    if (!existsSync(configuration.happyHomeDir)) {
      await mkdir(configuration.happyHomeDir, { recursive: true })
    }

    // Write atomically using rename
    await writeFile(tmpFile, JSON.stringify(updated, null, 2))
    await rename(tmpFile, configuration.sessionStateFile)

    return updated
  } finally {
    // Release lock
    await fileHandle.close()
    await unlink(lockFile).catch(() => { })
  }
}

/**
 * Save current session to persistent storage
 */
export async function saveCurrentSession(session: SavedSession): Promise<void> {
  await updateSessionState((state) => ({
    ...state,
    sessions: {
      ...state.sessions,
      [session.workingDirectory]: session,
    },
    lastActiveWorkingDirectory: session.workingDirectory,
  }))
  logger.debug(`Saved session state for ${session.workingDirectory}`)
}

/**
 * Update lastActiveAt timestamp for a session
 */
export async function touchSession(workingDirectory: string): Promise<void> {
  await updateSessionState((state) => {
    const session = state.sessions[workingDirectory]
    if (!session) return state

    return {
      ...state,
      sessions: {
        ...state.sessions,
        [workingDirectory]: {
          ...session,
          lastActiveAt: Date.now(),
        },
      },
    }
  })
}

/**
 * Load session for a specific directory
 */
export async function loadSessionForDirectory(
  workingDirectory: string
): Promise<SavedSession | null> {
  const state = await readSessionState()
  const session = state.sessions[workingDirectory]

  if (!session) {
    return null
  }

  if (isSessionExpired(session)) {
    // Clean up expired session
    logger.debug(`Session expired for ${workingDirectory}, cleaning up`)
    await updateSessionState((s) => {
      const { [workingDirectory]: _, ...rest } = s.sessions
      return { ...s, sessions: rest }
    })
    return null
  }

  return session
}

/**
 * Remove session for a specific directory
 */
export async function removeSession(workingDirectory: string): Promise<void> {
  await updateSessionState((state) => {
    const { [workingDirectory]: _, ...rest } = state.sessions
    return {
      ...state,
      sessions: rest,
      lastActiveWorkingDirectory: state.lastActiveWorkingDirectory === workingDirectory
        ? undefined
        : state.lastActiveWorkingDirectory,
    }
  })
  logger.debug(`Removed session state for ${workingDirectory}`)
}

/**
 * Clean up expired sessions
 */
export async function cleanupExpiredSessions(): Promise<number> {
  const state = await readSessionState()
  let cleanedCount = 0

  const validSessions: Record<string, SavedSession> = {}

  for (const [dir, session] of Object.entries(state.sessions)) {
    if (!isSessionExpired(session)) {
      validSessions[dir] = session
    } else {
      cleanedCount++
      logger.debug(`Cleaning up expired session for ${dir}`)
    }
  }

  if (cleanedCount > 0) {
    await updateSessionState((s) => ({
      ...s,
      sessions: validSessions,
    }))
  }

  return cleanedCount
}

/**
 * Encode Uint8Array to Base64 string
 */
export function encodeBase64(data: Uint8Array): string {
  return Buffer.from(data).toString('base64')
}

/**
 * Decode Base64 string to Uint8Array
 */
export function decodeBase64(data: string): Uint8Array {
  return new Uint8Array(Buffer.from(data, 'base64'))
}
