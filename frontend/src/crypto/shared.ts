import {
  CompactEncrypt, CompactSign, calculateJwkThumbprint, compactDecrypt, compactVerify,
  exportJWK, generateKeyPair, importJWK,
} from 'jose'
import { z } from 'zod'

const coordinate = z.string().regex(/^[A-Za-z0-9_-]{43}$/)
const publicKey = z.object({ kty: z.literal('EC'), crv: z.literal('P-256'), x: coordinate, y: coordinate }).strict()
const privateKey = publicKey.extend({ d: coordinate }).strict()
export const publicIdentity = z.object({ agreement: publicKey, signing: publicKey }).strict()
export const privateIdentity = z.object({ agreement: privateKey, signing: privateKey }).strict()
export type PublicIdentity = z.infer<typeof publicIdentity>
export type PrivateIdentity = z.infer<typeof privateIdentity>
const encoder = new TextEncoder()
const decoder = new TextDecoder('utf-8', { fatal: true })
const signedType = 'pinaki-vault-grant+jws'
const encryptedType = 'pinaki-vault-key+jwe'

const grantScope = z.object({
  vault: z.uuid(),
  epoch: z.number().int().positive().max(Number.MAX_SAFE_INTEGER),
  sender: z.uuid(),
  recipient: z.uuid(),
  recipientKey: coordinate,
}).strict()
export type GrantScope = z.infer<typeof grantScope>
const grantPayload = z.object({ binding: grantScope, envelope: z.string().max(4096) }).strict()

function publicPart({ kty, crv, x, y }: PublicIdentity['agreement']) {
  return { kty, crv, x, y }
}

export function getPublicIdentity(identity: PrivateIdentity): PublicIdentity {
  return { agreement: publicPart(identity.agreement), signing: publicPart(identity.signing) }
}

async function keyPair(alg: 'ECDH-ES' | 'ES256') {
  const { privateKey: key } = await generateKeyPair(alg, { extractable: true, crv: 'P-256' })
  const { kty, crv, x, y, d } = await exportJWK(key)
  return privateKey.parse({ kty, crv, x, y, d })
}

export async function generateIdentity(): Promise<PrivateIdentity> {
  const [agreement, signing] = await Promise.all([keyPair('ECDH-ES'), keyPair('ES256')])
  return { agreement, signing }
}

export async function fingerprints(identity: PublicIdentity) {
  const keys = publicIdentity.parse(identity)
  const [agreement, signing] = await Promise.all([
    calculateJwkThumbprint(keys.agreement, 'sha256'), calculateJwkThumbprint(keys.signing, 'sha256'),
  ])
  return { agreement, signing }
}

export async function sealGrant(
  root: Uint8Array<ArrayBuffer>, bindingInput: GrantScope, signer: PrivateIdentity['signing'],
  recipientKey: PublicIdentity['agreement'],
): Promise<string> {
  const binding = grantScope.parse(bindingInput)
  const recipient = publicKey.parse(recipientKey)
  if (root.length !== 32 || await calculateJwkThumbprint(recipient, 'sha256') !== binding.recipientKey) {
    throw new Error('The recipient key does not match its verified fingerprint.')
  }
  const [encryptTo, signAs] = await Promise.all([
    importJWK(recipient, 'ECDH-ES'), importJWK(privateKey.parse(signer), 'ES256'),
  ])
  const envelope = await new CompactEncrypt(root)
    .setProtectedHeader({ alg: 'ECDH-ES', enc: 'A256GCM', typ: encryptedType, kid: binding.recipientKey })
    .encrypt(encryptTo)
  return new CompactSign(encoder.encode(JSON.stringify({ binding, envelope })))
    .setProtectedHeader({ alg: 'ES256', typ: signedType })
    .sign(signAs)
}

export async function openGrant(
  grant: string, expectedInput: GrantScope, senderPin: string, senderKey: PublicIdentity['signing'],
  recipient: PrivateIdentity['agreement'],
): Promise<Uint8Array<ArrayBuffer>> {
  const expected = grantScope.parse(expectedInput)
  const sender = publicKey.parse(senderKey)
  if (await calculateJwkThumbprint(sender, 'sha256') !== coordinate.parse(senderPin)) {
    throw new Error('The grantor key does not match its verified fingerprint.')
  }
  if (await calculateJwkThumbprint(publicPart(recipient), 'sha256') !== expected.recipientKey) {
    throw new Error('Grant is bound to a different recipient key.')
  }
  if (grant.length > 8192) throw new Error('Grant is too large.')
  const verifier = await importJWK(sender, 'ES256')
  const signed = await compactVerify(grant, verifier, { algorithms: ['ES256'] })
  if (signed.protectedHeader.typ !== signedType) throw new Error('Invalid grant type.')
  const { binding, envelope } = grantPayload.parse(JSON.parse(decoder.decode(signed.payload)))
  for (const key of Object.keys(expected) as Array<keyof GrantScope>) {
    if (binding[key] !== expected[key]) throw new Error('Grant scope does not match.')
  }
  const key = await importJWK(privateKey.parse(recipient), 'ECDH-ES')
  const decrypted = await compactDecrypt(envelope, key, {
    keyManagementAlgorithms: ['ECDH-ES'], contentEncryptionAlgorithms: ['A256GCM'],
  })
  if (decrypted.protectedHeader.typ !== encryptedType ||
      decrypted.protectedHeader.kid !== expected.recipientKey || decrypted.plaintext.length !== 32) {
    decrypted.plaintext.fill(0)
    throw new Error('Invalid shared vault key.')
  }
  const root = Uint8Array.from(decrypted.plaintext)
  decrypted.plaintext.fill(0)
  return root
}
