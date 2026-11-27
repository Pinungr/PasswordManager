import Papa from 'papaparse'
import { useState } from 'react'
import { blank, credential, emptyField, fieldType } from './data'
import type { Credential, FieldType, Limits, VaultRecord } from './data'

type Mapping = { column: string; label: string; type: FieldType }
type Table = { headers: string[]; rows: Record<string, string>[] }

export function CsvImport({ items, limits, importOne, exportEncrypted }: {
  items: VaultRecord[]; limits: Limits; importOne: (value: Credential) => Promise<void>
  exportEncrypted: () => Promise<void>
}) {
  const [table, setTable] = useState<Table>()
  const [name, setName] = useState('')
  const [mapping, setMapping] = useState<Mapping[]>([{ column: '', label: '', type: 'secret' }])
  const [status, setStatus] = useState('')
  const [busy, setBusy] = useState(false)
  const [previewed, setPreviewed] = useState(false)
  const existing = new Set(items.map((item) => item.value.name.toLowerCase()))
  function read(file: File) {
    setStatus(''); setTable(undefined); setPreviewed(false)
    if (file.size > 20 * 1024 * 1024) { setStatus('Use a CSV file of 20 MB or less.'); return }
    Papa.parse<Record<string, string>>(file, {
      header: true, skipEmptyLines: 'greedy',
      complete: ({ data, meta, errors }) => {
        if (errors.length || !meta.fields?.length || meta.renamedHeaders) {
          setStatus('CSV rows must match unique column headings.'); return
        }
        setTable({ headers: meta.fields, rows: data })
        setName('')
        setMapping([{ column: '', label: '', type: 'secret' }])
      },
      error: () => setStatus('The CSV file could not be read.'),
    })
  }
  function review() {
    const names = new Set(existing)
    return table?.rows.map((row) => {
      const item: Credential = { ...blank(), name: row[name] ?? '',
        fields: mapping.map(({ column, label, type }) => ({ ...emptyField(label, type), value: row[column] ?? '' })) }
      if (!credential.safeParse(item).success || item.fields.some((field) =>
        new TextEncoder().encode(field.value).length > limits.max_value_bytes)) return { item, status: 'Invalid' }
      const normalized = item.name.toLowerCase()
      if (names.has(normalized)) return { item, status: 'Duplicate' }
      names.add(normalized)
      return { item, status: 'Ready' }
    }) ?? []
  }
  const configured = Boolean(name && mapping.every((field) => field.column && field.label.trim()))
  const rows = previewed && configured ? review() : []
  const ready = rows.filter((row) => row.status === 'Ready').length
  return <div className="admin-stack">
    <section className="vault-panel editor admin-form">
      <h2>CSV import</h2>
      <p className="muted">CSV content is parsed and encrypted in this browser.</p>
      <label>CSV file<input type="file" accept=".csv,text/csv" disabled={busy}
        onChange={(event) => { const file = event.target.files?.[0]; if (file) read(file) }} /></label>
      {table && <>
        <label>Credential name column<select value={name} disabled={busy} onChange={(event) => {
          setName(event.target.value); setPreviewed(false)
        }}><option value="">Choose a column</option>{table.headers.map((head) => <option key={head}>{head}</option>)}</select></label>
        {mapping.map((field, index) => <fieldset className="field-row" key={index}>
          <label>Source column<select value={field.column} disabled={busy} onChange={(event) => {
            setPreviewed(false); setMapping(mapping.map((entry, i) => i === index ? { ...entry, column: event.target.value,
              label: entry.label || event.target.value } : entry))
          }}><option value="">Choose a column</option>{table.headers.map((head) => <option key={head}>{head}</option>)}</select></label>
          <label>Field type<select value={field.type} disabled={busy} onChange={(event) => {
            setPreviewed(false); setMapping(mapping.map((entry, i) => i === index ? { ...entry, type: fieldType.parse(event.target.value) } : entry))
          }}>{fieldType.options.map((type) => <option key={type}>{type}</option>)}</select></label>
          <label>Field name<input value={field.label} disabled={busy} onChange={(event) => {
            setPreviewed(false); setMapping(mapping.map((entry, i) => i === index ? { ...entry, label: event.target.value } : entry))
          }} /></label>
          <button className="secondary" type="button" disabled={busy || mapping.length === 1}
            onClick={() => { setPreviewed(false); setMapping(mapping.filter((_, i) => i !== index)) }}>Remove mapping</button>
        </fieldset>)}
        <div className="actions"><button className="secondary" disabled={busy || mapping.length >= limits.max_fields}
          onClick={() => { setPreviewed(false); setMapping([...mapping, { column: '', label: '', type: 'secret' }]) }}>Add field mapping</button>
          <button className="primary" disabled={busy || !configured} onClick={() => setPreviewed(true)}>Preview import</button></div>
      </>}
      {previewed && <div className="admin-stack"><h3>Preview</h3>
        <p>{ready} ready · {rows.filter((row) => row.status === 'Duplicate').length} duplicates · {rows.filter((row) => row.status === 'Invalid').length} invalid</p>
        <ul>{rows.slice(0, 20).map((row, index) => <li key={index}>{row.item.name || 'Unnamed'} · {row.status}</li>)}</ul>
        <button className="primary fit" disabled={busy || !ready} onClick={() => {
          if (!window.confirm('Import ' + ready + ' credentials?')) return
          setBusy(true)
          void (async () => {
            let done = 0
            try {
              for (const row of rows) {
                if (row.status !== 'Ready') continue
                await importOne(row.item)
                done++
              }
              setStatus('Imported ' + done + ' credentials.')
              setTable(undefined); setPreviewed(false)
            } catch { setStatus('Import paused after ' + done + ' credentials. Preview the remaining rows before retrying.') }
            finally { setBusy(false) }
          })()
        }}>Import valid credentials</button>
      </div>}
      {status && <p role="status">{status}</p>}
    </section>
    <section className="vault-panel editor admin-form"><h2>Encrypted vault export</h2>
      <button className="secondary fit" disabled={busy} onClick={() => {
        void exportEncrypted().then(() => setStatus('Encrypted export created.')).catch(() => setStatus('Encrypted export failed.'))
      }}>Export encrypted vault</button>
    </section>
  </div>
}
