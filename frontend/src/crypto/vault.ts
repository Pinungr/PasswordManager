import { decode, encode, generateVaultRoot, importVaultRoot } from './record'
import type { Envelope } from './record'
import { aesGcm } from './browser'

export interface VaultKeys {
  profile: 1
  salt: string
  password: Envelope
  recovery: Envelope
}

export interface PersonalVault { id: string; revision: number; keys: VaultKeys }
type Purpose = 'master-password' | 'recovery-key'

function derive(password: string, salt: Uint8Array, profile: number): Promise<Uint8Array<ArrayBuffer>> {
  const worker = new Worker(new URL('./vault-kdf.worker.ts', import.meta.url), { type: 'module' })
  return new Promise((resolve, reject) => {
    const timer = window.setTimeout(() => fail(), 30000)
    function fail() {
      window.clearTimeout(timer)
      worker.terminate()
      reject(new Error('Vault key derivation failed.'))
    }
    worker.onerror = fail
    worker.onmessage = ({ data }: MessageEvent<Uint8Array<ArrayBuffer> | null>) => {
      if (!data || data.length !== 32) { fail(); return }
      window.clearTimeout(timer)
      worker.terminate()
      resolve(data)
    }
    worker.postMessage({ password, salt, profile })
  })
}

function binding(purpose: Purpose, vault: string, owner: string) {
  return new TextEncoder().encode(JSON.stringify(['pinaki-securevault-v1', purpose, vault, owner, 1]))
}

async function wrap(bytes: Uint8Array<ArrayBuffer>, raw: Uint8Array<ArrayBuffer>, additionalData: Uint8Array<ArrayBuffer>): Promise<Envelope> {
  const iv = crypto.getRandomValues(new Uint8Array(12))
  const result = await aesGcm('encrypt', bytes, iv, raw, additionalData)
  return { version: 1, nonce: encode(iv), ciphertext: encode(result) }
}

async function unwrap(bytes: Uint8Array<ArrayBuffer>, envelope: Envelope, additionalData: Uint8Array<ArrayBuffer>) {
  const iv = decode(envelope.nonce)
  const ciphertext = decode(envelope.ciphertext)
  if (envelope.version !== 1 || iv.length !== 12 || ciphertext.length !== 48 || bytes.length !== 32) {
    throw new Error('Invalid key envelope.')
  }
  return aesGcm('decrypt', bytes, iv, ciphertext, additionalData)
}

export async function openVault(input: string, vault: PersonalVault, owner: string, recovery: boolean) {
  const rawKey = recovery ? decode(input.trim()) : await derive(input, decode(vault.keys.salt), vault.keys.profile)
  try {
    const envelope = recovery ? vault.keys.recovery : vault.keys.password
    return await unwrap(rawKey, envelope, binding(recovery ? 'recovery-key' : 'master-password', vault.id, owner))
  } finally {
    rawKey.fill(0)
  }
}

export async function newVaultKeys(password: string, vault: string, owner: string, root: Uint8Array<ArrayBuffer>) {
  const salt = crypto.getRandomValues(new Uint8Array(16))
  const recovery = generateVaultRoot()
  const derived = await derive(password, salt, 1)
  try {
    const keys: VaultKeys = {
      profile: 1, salt: encode(salt),
      password: await wrap(derived, root, binding('master-password', vault, owner)),
      recovery: await wrap(recovery, root, binding('recovery-key', vault, owner)),
    }
    return { keys, recovery: encode(recovery), root: await importVaultRoot(root) }
  } finally {
    derived.fill(0)
    recovery.fill(0)
  }
}
