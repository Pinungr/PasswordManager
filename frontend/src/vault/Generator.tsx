import { useState } from 'react'
import { defaults, generatePassphrase, generatePassword } from '../crypto/password'
import type { PasswordGroup } from '../crypto/password'

export function Generator({ copy }: { copy: (value: string) => Promise<void> }) {
  const [passphrase, setPassphrase] = useState(false)
  const [length, setLength] = useState(24)
  const [count, setCount] = useState(6)
  const [groups, setGroups] = useState<PasswordGroup[]>(defaults)
  const [exclude, setExclude] = useState(false)
  const [value, setValue] = useState('')
  const [status, setStatus] = useState('')
  const [busy, setBusy] = useState(false)

  async function generate() {
    setBusy(true)
    setStatus('')
    try { setValue(passphrase ? await generatePassphrase(count) : generatePassword(length, groups, exclude)) }
    catch { setStatus('Password generation failed.') }
    finally { setBusy(false) }
  }

  return <section className="vault-panel editor generator">
    <label className="checkbox"><input type="checkbox" checked={passphrase}
      onChange={(event) => { setPassphrase(event.target.checked); setValue('') }} /> Passphrase mode</label>
    <label>{passphrase ? 'Words · ' + count : 'Length · ' + length}
      <input type="range" min={passphrase ? 6 : 8} max={passphrase ? 12 : 128} value={passphrase ? count : length}
        onChange={(event) => { setValue(''); (passphrase ? setCount : setLength)(event.target.valueAsNumber) }} /></label>
    {!passphrase && <div className="actions">
      {defaults.map((group) => <label key={group} className="checkbox">
        <input type="checkbox" checked={groups.includes(group)} onChange={(event) => {
          setValue('')
          setGroups(event.target.checked ? [...groups, group] : groups.filter((item) => item !== group))
        }} /> {group}</label>)}
      <label className="checkbox"><input type="checkbox" checked={exclude}
        onChange={(event) => { setExclude(event.target.checked); setValue('') }} /> Exclude ambiguous characters</label>
    </div>}
    {value && <><output className="recovery-code">{value}</output>
      <p className="muted">Strength · {passphrase || (groups.length >= 2 && length >= 16) || length >= 24 ? 'Strong' : 'Moderate'}</p></>}
    <div className="actions">
      <button type="button" className="primary" disabled={busy || (!passphrase && groups.length === 0)}
        onClick={() => void generate()}>{value ? 'Regenerate' : 'Generate'}</button>
      <button type="button" className="secondary" disabled={!value} onClick={() => {
        void copy(value).then(() => setStatus('Copied.')).catch(() => setStatus('Clipboard unavailable.'))
      }}>Copy</button>
    </div>
    {status && <p role="status" className="muted">{status}</p>}
  </section>
}
