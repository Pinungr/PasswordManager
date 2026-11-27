import { p256 } from '@noble/curves/nist.js'
import { sha256 } from '@noble/hashes/sha2.js'
import { concatBytes } from '@noble/hashes/utils.js'
import { aesGcm } from './browser'
import { decode, encode } from './record'
import { publicIdentity } from './shared'
import type { PrivateIdentity, PublicIdentity } from './shared'

type PublicKey = PublicIdentity['agreement']
type PrivateKey = PrivateIdentity['agreement']
const encoder = new TextEncoder()
const decoder = new TextDecoder('utf-8', { fatal: true })
const signedType = 'pinaki-vault-grant+jws'
const encryptedType = 'pinaki-vault-key+jwe'
const jsonPart = (value: unknown) => encode(encoder.encode(JSON.stringify(value)))
const jsonValue = (value: string): unknown => JSON.parse(decoder.decode(decode(value)))

function toPoint(key: PublicKey) {
  return concatBytes(Uint8Array.of(4), decode(key.x), decode(key.y))
}

function publicJwk(secretKey: Uint8Array): PublicKey {
  const point = p256.getPublicKey(secretKey, false)
  return { kty: 'EC', crv: 'P-256', x: encode(point.subarray(1, 33)), y: encode(point.subarray(33)) }
}

export function generateHttpKey(): PrivateKey {
  const { secretKey } = p256.keygen()
  try {
    return { ...publicJwk(secretKey), d: encode(secretKey) }
  } finally {
    secretKey.fill(0)
  }
}

export function httpThumbprint({ crv, kty, x, y }: PublicKey): string {
  return encode(sha256(encoder.encode(JSON.stringify({ crv, kty, x, y }))))
}

function grantKey(secret: Uint8Array, peer: PublicKey) {
  const point = p256.getSharedSecret(secret, toPoint(peer), false)
  try {
    const algorithm = encoder.encode('A256GCM')
    // RFC 7518 §4.6.2. Counter, P-256 x-coordinate, length-prefixed algorithm,
    // empty PartyUInfo and PartyVInfo, and the output length in bits.
    return sha256(concatBytes(
      Uint8Array.of(0, 0, 0, 1), point.subarray(1, 33),
      Uint8Array.of(0, 0, 0, algorithm.length), algorithm,
      new Uint8Array(8), Uint8Array.of(0, 0, 1, 0),
    ))
  } finally {
    point.fill(0)
  }
}

export async function encryptHttpGrant(root: Uint8Array<ArrayBuffer>, kid: string, recipient: PublicKey) {
  const { secretKey } = p256.keygen()
  let key: Uint8Array | undefined
  try {
    const header = jsonPart({
      alg: 'ECDH-ES', enc: 'A256GCM', typ: encryptedType, kid, epk: publicJwk(secretKey),
    })
    const iv = crypto.getRandomValues(new Uint8Array(12))
    const derived = grantKey(secretKey, recipient)
    key = derived
    const sealed = await aesGcm('encrypt', derived, iv, root, encoder.encode(header))
    return [header, '', encode(iv), encode(sealed.subarray(0, -16)), encode(sealed.subarray(-16))].join('.')
  } finally {
    secretKey.fill(0)
    key?.fill(0)
  }
}

export function signHttpGrant(payload: unknown, signer: PrivateKey) {
  const message = jsonPart({ alg: 'ES256', typ: signedType }) + '.' + jsonPart(payload)
  const secret = decode(signer.d)
  try {
    return message + '.' + encode(p256.sign(encoder.encode(message), secret))
  } finally {
    secret.fill(0)
  }
}

export function verifyHttpGrant(grant: string, sender: PublicKey) {
  const parts = grant.split('.')
  if (parts.length !== 3) throw new Error('Invalid shared vault grant.')
  const [header, payload, signature] = parts as [string, string, string]
  const parsed = jsonValue(header) as Record<string, unknown> | null
  if (!parsed || Object.keys(parsed).length !== 2 || parsed.alg !== 'ES256' || parsed.typ !== signedType ||
      !p256.verify(decode(signature), encoder.encode(header + '.' + payload), toPoint(sender), { lowS: false })) {
    throw new Error('Invalid shared vault grant.')
  }
  return jsonValue(payload)
}

export async function decryptHttpGrant(envelope: string, kid: string, recipient: PrivateKey) {
  const parts = envelope.split('.')
  if (parts.length !== 5 || parts[1] !== '') throw new Error('Invalid shared vault key.')
  const [header, , nonce, ciphertext, tag] = parts as [string, string, string, string, string]
  const parsed = jsonValue(header) as Record<string, unknown> | null
  if (!parsed || Object.keys(parsed).length !== 5 || parsed.alg !== 'ECDH-ES' || parsed.enc !== 'A256GCM' ||
      parsed.typ !== encryptedType || parsed.kid !== kid) {
    throw new Error('Invalid shared vault key.')
  }
  const epk = publicIdentity.shape.agreement.parse(parsed.epk)
  const iv = decode(nonce)
  const body = decode(ciphertext)
  const authenticationTag = decode(tag)
  if (iv.length !== 12 || body.length !== 32 || authenticationTag.length !== 16) {
    throw new Error('Invalid shared vault key.')
  }
  const secret = decode(recipient.d)
  try {
    const key = grantKey(secret, epk)
    try {
      return await aesGcm('decrypt', key, iv, concatBytes(body, authenticationTag), encoder.encode(header))
    } finally {
      key.fill(0)
    }
  } finally {
    secret.fill(0)
  }
}
