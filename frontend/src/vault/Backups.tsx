import { useEffect, useState } from 'react'
import { api } from '../services/api'

type Backup = { name: string; bytes: number; timestamp: number }
type BackupList = { items: Backup[]; pending_restore: boolean; schedule: string; retention_days: number; timezone: string }

export function Backups({ csrf }: { csrf: string }) {
  const [data, setData] = useState<BackupList>()
  const [selection, setSelection] = useState<Backup | null>(null)
  const [version, reload] = useState(0)
  const [busy, setBusy] = useState(false)
  const [status, setStatus] = useState('')
  const [error, setError] = useState('')
  useEffect(() => {
    let live = true
    void api<BackupList>('backups').then((result) => { if (live) setData(result) })
      .catch((failure) => { if (live) setError(failure instanceof Error ? failure.message : 'Backup history unavailable.') })
    return () => { live = false }
  }, [version])

  async function run(work: () => Promise<string>) {
    if (busy) return
    setBusy(true); setError(''); setStatus('')
    try { setStatus(await work()); reload((value) => value + 1) }
    catch (failure) { setError(failure instanceof Error ? failure.message : 'Backup operation failed.') }
    finally { setBusy(false) }
  }
  const last = data?.items[0]

  return <div className="admin-stack">
    {error && <p className="error" role="alert">{error}</p>}
    {status && <p role="status">{status}</p>}
    {!data && !error && <p role="status">Loading backup history…</p>}
    {data && <>
      {data.pending_restore && <p className="vault-panel" role="status">
        Restore is staged. The service will replace the live database on its next restart.
      </p>}
      <div className="metrics">
        <div className="vault-panel metric"><span>Last successful backup</span>
          <strong>{last ? new Date(last.timestamp * 1000).toLocaleDateString() : 'None'}</strong></div>
        <div className="vault-panel metric"><span>Backup size</span><strong>{last ? Math.ceil(last.bytes / 1024) + ' KB' : '—'}</strong></div>
        <div className="vault-panel metric"><span>Daily schedule · {data.timezone}</span><strong>{data.schedule}</strong></div>
        <div className="vault-panel metric"><span>Retention</span><strong>{data.retention_days} days</strong></div>
      </div>
      <section className="vault-panel admin-stack">
        <div className="list-head"><h2>Backup history</h2>
          <div className="actions">
            <button className="secondary" disabled={busy || data.pending_restore} onClick={() => {
              if (window.confirm('Delete backups that are past the retention period?')) void run(async () => {
                const result = await api<{ deleted: number }>('backups/retention', {}, csrf)
                return 'Removed ' + result.deleted + ' expired backups.'
              })
            }}>Delete expired backups</button>
            <button className="primary" disabled={busy || data.pending_restore}
              onClick={() => void run(async () => { await api('backups', {}, csrf); return 'Verified encrypted backup created.' })}>
              Create backup now</button>
          </div>
        </div>
        {!data.items.length && <p className="muted">No encrypted backups are available.</p>}
        {data.items.length > 0 && <div className="table-wrap"><table><thead><tr>
          <th scope="col">Backup</th><th scope="col">Created</th><th scope="col">Size</th><th scope="col">Actions</th>
        </tr></thead><tbody>{data.items.map((entry) => <tr key={entry.name}>
          <td>{entry.name}</td><td>{new Date(entry.timestamp * 1000).toLocaleString()}</td>
          <td>{Math.ceil(entry.bytes / 1024)} KB</td><td><div className="actions">
            <button className="secondary" disabled={busy || data.pending_restore} onClick={() => void run(async () => {
              await api('backups/' + entry.name + '/verify', {}, csrf); return 'Backup integrity verified.'
            })}>Verify backup</button>
            <a className="secondary" href={'/api/v1/backups/' + entry.name + '/export'}>Export encrypted backup</a>
            <button className="secondary" disabled={busy || data.pending_restore} onClick={() => setSelection(entry)}>Restore backup</button>
          </div></td>
        </tr>)}</tbody></table></div>}
      </section>
    </>}
    {selection && <form className="vault-panel editor admin-form" onSubmit={(event) => {
      event.preventDefault()
      const form = new FormData(event.currentTarget)
      void run(async () => {
        await api('backups/' + selection.name + '/restore', {
          confirmation: form.get('confirmation'), password: form.get('password'),
        }, csrf)
        setSelection(null)
        return 'Restore staged. Restart SecureVault to apply it.'
      })
    }}>
      <h2>Confirm database restore</h2><p>{selection.name}</p>
      <p className="error">This will replace the live database and end every session at the next restart.</p>
      <label>Administrator account password<input name="password" type="password" autoComplete="current-password" required /></label>
      <label>Type RESTORE to confirm<input name="confirmation" autoComplete="off" required pattern="RESTORE" /></label>
      <div className="actions"><button className="primary" disabled={busy}>Stage restore</button>
        <button className="secondary" type="button" disabled={busy} onClick={() => setSelection(null)}>Cancel</button></div>
    </form>}
  </div>
}
