import { argon2id } from '@noble/hashes/argon2.js'

export function deriveVaultKey(password: string, salt: Uint8Array, profile: number) {
  if (profile !== 1 || salt.length !== 16) throw new Error('Unsupported vault key profile')
  const bytes = new TextEncoder().encode(password)
  try {
    return argon2id(bytes, salt, { version: 0x13, m: 65536, t: 3, p: 4, dkLen: 32 })
  } finally {
    bytes.fill(0)
  }
}
