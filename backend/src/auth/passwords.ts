import { hash, verify } from '@node-rs/argon2'

// Argon2id with sensible defaults. @node-rs/argon2 defaults to argon2id.
export function hashPassword(plain: string): Promise<string> {
  return hash(plain)
}

export async function verifyPassword(storedHash: string, plain: string): Promise<boolean> {
  try {
    return await verify(storedHash, plain)
  } catch {
    // Malformed hash etc. — treat as a failed verification, never throw to caller.
    return false
  }
}
