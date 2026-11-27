type Bytes = Uint8Array<ArrayBuffer>

export function randomUuid(): string {
  if (typeof crypto.randomUUID === 'function') return crypto.randomUUID()
  const bytes = crypto.getRandomValues(new Uint8Array(16))
  bytes[6] = (bytes[6]! & 0x0f) | 0x40
  bytes[8] = (bytes[8]! & 0x3f) | 0x80
  const hex = Array.from(bytes, (byte) => byte.toString(16).padStart(2, '0')).join('')
  return [hex.slice(0, 8), hex.slice(8, 12), hex.slice(12, 16), hex.slice(16, 20), hex.slice(20)].join('-')
}

export function testCryptoFallback(): boolean {
  return !crypto.subtle && window.location.protocol === 'http:'
}

export async function aesGcm(
  operation: 'encrypt' | 'decrypt', key: CryptoKey | Bytes, iv: Bytes, data: Bytes, additionalData: Bytes,
): Promise<Bytes> {
  if (key instanceof Uint8Array && testCryptoFallback()) {
    const { gcm } = await import('@noble/ciphers/aes.js')
    const cipher = gcm(key, iv, additionalData)
    try {
      return Uint8Array.from(cipher[operation](data))
    } catch (error) {
      if (operation === 'decrypt') throw new DOMException('Could not authenticate ciphertext.', 'OperationError')
      throw error
    }
  }
  const imported = key instanceof Uint8Array
    ? await crypto.subtle.importKey('raw', key, 'AES-GCM', false, [operation])
    : key
  return new Uint8Array(await crypto.subtle[operation](
    { name: 'AES-GCM', iv, additionalData, tagLength: 128 }, imported, data,
  ))
}
