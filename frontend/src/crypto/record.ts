const encoder = new TextEncoder()
const uuid = /^[0-9a-f]{8}(?:-[0-9a-f]{4}){3}-[0-9a-f]{12}$/

interface RecordContext {
  vaultId: string
  recordId: string
  version: number
  epoch?: number
  purpose?: 'shared-identity'
}

export interface Envelope {
  version: 1
  nonce: string
  ciphertext: string
}

export function encode(bytes: Uint8Array): string {
  let raw = ''
  for (let offset = 0; offset < bytes.length; offset += 8192) {
    raw += String.fromCharCode(...bytes.subarray(offset, offset + 8192))
  }
  return btoa(raw).replaceAll('+', '-').replaceAll('/', '_').replace(/=+$/, '')
}

export function decode(value: string): Uint8Array<ArrayBuffer> {
  if (!/^[a-zA-Z0-9_-]+$/.test(value)) throw new Error('Invalid envelope encoding')
  const bytes = Uint8Array.from(atob(value.replaceAll('-', '+').replaceAll('_', '/')), (c) =>
    c.charCodeAt(0),
  )
  if (encode(bytes) !== value) throw new Error('Invalid envelope encoding')
  return bytes
}

export function generateVaultRoot(): Uint8Array<ArrayBuffer> {
  return crypto.getRandomValues(new Uint8Array(32))
}

export async function importVaultRoot(root: Uint8Array<ArrayBuffer>): Promise<CryptoKey> {
  if (root.length !== 32) throw new Error('Invalid vault root')
  return crypto.subtle.importKey('raw', root, 'HKDF', false, ['deriveKey'])
}

async function recordKey(root: CryptoKey, context: RecordContext) {
  const { vaultId, recordId, version } = context
  if (![vaultId, recordId].every((id) => uuid.test(id)) || !Number.isSafeInteger(version) || version < 1) {
    throw new Error('Invalid record binding')
  }
  return crypto.subtle.deriveKey(
    {
      name: 'HKDF',
      hash: 'SHA-256',
      salt: encoder.encode(vaultId),
      info: encoder.encode(JSON.stringify(['pinaki-securevault-v1', 'record-key', recordId, ...(context.epoch ? [context.epoch] : []), ...(context.purpose ? [context.purpose] : [])])),
    },
    root,
    { name: 'AES-GCM', length: 256 },
    false,
    ['encrypt', 'decrypt'],
  )
}

function recordData(context: RecordContext) {
  return encoder.encode(JSON.stringify([
    'pinaki-securevault-v1', context.purpose ?? 'credential', context.vaultId, context.recordId, context.version,
    ...(context.epoch ? [context.epoch] : []),
  ]))
}

export async function sealRecord(
  root: CryptoKey, context: RecordContext, plaintext: Uint8Array<ArrayBuffer>,
): Promise<Envelope> {
  const key = await recordKey(root, context)
  const iv = crypto.getRandomValues(new Uint8Array(12))
  const ciphertext = await crypto.subtle.encrypt(
    { name: 'AES-GCM', iv, additionalData: recordData(context), tagLength: 128 }, key, plaintext,
  )
  return { version: 1, nonce: encode(iv), ciphertext: encode(new Uint8Array(ciphertext)) }
}

export async function openRecord(root: CryptoKey, context: RecordContext, envelope: Envelope) {
  if (envelope.version !== 1) throw new Error('Unsupported record envelope')
  const iv = decode(envelope.nonce)
  const ciphertext = decode(envelope.ciphertext)
  if (iv.length !== 12 || ciphertext.length < 16) throw new Error('Invalid envelope length')
  const key = await recordKey(root, context)
  return new Uint8Array(await crypto.subtle.decrypt(
    { name: 'AES-GCM', iv, additionalData: recordData(context), tagLength: 128 }, key, ciphertext,
  ))
}
