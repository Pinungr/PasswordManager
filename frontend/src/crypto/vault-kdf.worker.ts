import { deriveVaultKey } from './vault-kdf'

self.onmessage = ({ data }: MessageEvent<{ password: string; salt: Uint8Array; profile: number }>) => {
  try {
    const key = deriveVaultKey(data.password, data.salt, data.profile)
    self.postMessage(key, { transfer: [key.buffer] })
  } catch {
    self.postMessage(null)
  }
}
