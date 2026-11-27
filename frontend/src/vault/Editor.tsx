import { ArrowDown, ArrowUp, Eye, EyeOff, Plus, Trash2, WandSparkles } from 'lucide-react'
import { useEffect, useState } from 'react'
import { generatePassword } from '../crypto/password'
import { credential, emptyField, fieldType, templates } from './data'
import type { CatalogEntry, Credential, Field, Limits } from './data'

export function Editor({ value, limits, catalog, save, close }: {
  value: Credential
  limits: Limits
  catalog: { category: CatalogEntry[]; environment: CatalogEntry[] }
  save: (value: Credential) => Promise<void>
  close: () => void
}) {
  const [draft, setDraft] = useState(value)
  const [visible, setVisible] = useState<string[]>([])
  const [error, setError] = useState('')
  const [saving, setSaving] = useState(false)
  const parsed = credential.safeParse(draft)
  const oversized = draft.fields.some((field) => new TextEncoder().encode(field.value).length > limits.max_value_bytes)
  const dirty = JSON.stringify(draft) !== JSON.stringify(value)
  const valid = parsed.success && !oversized && draft.fields.length <= limits.max_fields

  useEffect(() => {
    if (!dirty) return
    const confirmLeave = (event: BeforeUnloadEvent) => event.preventDefault()
    window.addEventListener('beforeunload', confirmLeave)
    return () => window.removeEventListener('beforeunload', confirmLeave)
  }, [dirty])

  function change<Key extends keyof Credential>(key: Key, next: Credential[Key]) {
    setDraft((previous) => ({ ...previous, [key]: next }))
  }
  function editField(id: string, next: Partial<Field>) {
    change('fields', draft.fields.map((field) => field.id === id ? { ...field, ...next } : field))
  }
  function move(index: number, step: number) {
    const fields = draft.fields.slice()
    const target = index + step
    ;[fields[index], fields[target]] = [fields[target]!, fields[index]!]
    change('fields', fields)
  }

  return (
    <form className="vault-panel editor" autoComplete="off" onSubmit={async (event) => {
      event.preventDefault()
      if (!valid || saving) return
      setSaving(true)
      setError('')
      try { await save(parsed.data) } catch (failure) {
        setError(failure instanceof Error ? failure.message : 'Save failed.')
      } finally { setSaving(false) }
    }}>
      <h2>{value.name ? 'Edit credential' : 'Add credential'}</h2>
      <label>Credential name<input maxLength={200} value={draft.name}
        onChange={(event) => change('name', event.target.value)} /></label>
      {!value.name && <label>Template
        <select defaultValue="" onChange={(event) => {
          const template = templates[event.target.value]
          if (!template) return
          if (draft.fields.some((field) => field.label || field.value) && !window.confirm('Replace the current fields?')) {
            event.currentTarget.value = ''
            return
          }
          change('fields', template.map(([label, type]) => emptyField(label, type)))
        }}>
          <option value="">Choose a template</option>
          {Object.keys(templates).map((name) =>
            <option disabled={templates[name]!.length > limits.max_fields} key={name}>{name}</option>)}
        </select>
      </label>}
      <div className="metadata-grid">
        {(['category', 'environment'] as const).map((key) => (
          <label key={key} className="capitalized">{key}<select value={draft[key]}
            onChange={(event) => change(key, event.target.value)}>
            <option value="">None</option>
            {draft[key] && !catalog[key].some((item) => item.id === draft[key]) &&
              <option value={draft[key]}>{draft[key]}</option>}
            {catalog[key].filter((item) => item.active || item.id === draft[key]).map((item) =>
              <option key={item.id} value={item.id}>{item.name}</option>)}
          </select></label>
        ))}
        <label>Folder<input maxLength={200} value={draft.folder}
          onChange={(event) => change('folder', event.target.value)} /></label>
      </div>
      <h3>Credential values</h3>
      {draft.fields.map((field, index) => (
        <fieldset key={field.id} className="field-row">
          <label>Field name<input value={field.label} maxLength={200} onChange={(event) =>
            editField(field.id, { label: event.target.value })} /></label>
          <label>Field type<select value={field.type} onChange={(event) =>
            editField(field.id, { type: fieldType.parse(event.target.value) })}>
            <option value="text">Text</option><option value="secret">Secret</option>
            <option value="multiline">Multiline text</option><option value="url">URL</option>
          </select></label>
          <label className="field-value">Value
            {field.type === 'multiline' ? (
              <textarea value={field.value} onChange={(event) => editField(field.id, { value: event.target.value })} />
            ) : (
              <input value={field.value} type={field.type === 'secret' && !visible.includes(field.id) ? 'password' : 'text'}
                autoComplete="off" spellCheck={false} onChange={(event) => editField(field.id, { value: event.target.value })} />
            )}
          </label>
          <div className="actions field-actions">
            <button type="button" className="icon-button" aria-label="Move field up" disabled={index === 0}
              onClick={() => move(index, -1)}><ArrowUp size={16} /></button>
            <button type="button" className="icon-button" aria-label="Move field down" disabled={index === draft.fields.length - 1}
              onClick={() => move(index, 1)}><ArrowDown size={16} /></button>
            {field.type === 'secret' && <>
              <button type="button" className="icon-button"
                aria-label={visible.includes(field.id) ? 'Mask field' : 'Reveal field'} onClick={() => {
                  if (visible.includes(field.id)) setVisible((current) => current.filter((id) => id !== field.id))
                  else {
                    setVisible((current) => [...current, field.id])
                    window.setTimeout(() => setVisible((current) => current.filter((id) => id !== field.id)), limits.reveal_seconds * 1000)
                  }
                }}>{visible.includes(field.id) ? <EyeOff size={16} /> : <Eye size={16} />}</button>
              <button type="button" className="icon-button" aria-label="Generate password"
                onClick={() => editField(field.id, { value: generatePassword() })}><WandSparkles size={16} /></button>
            </>}
            <button type="button" className="icon-button" aria-label="Remove field" disabled={draft.fields.length === 1}
              onClick={() => change('fields', draft.fields.filter((item) => item.id !== field.id))}><Trash2 size={16} /></button>
          </div>
        </fieldset>
      ))}
      <button className="secondary fit" type="button" disabled={draft.fields.length >= limits.max_fields}
        onClick={() => change('fields', [...draft.fields, emptyField()])}><Plus size={16} /> Add another value</button>
      <label>Notes<textarea maxLength={20000} value={draft.notes}
        onChange={(event) => change('notes', event.target.value)} /></label>
      <div className="metadata-grid">
        <label>Tags<input maxLength={2000} value={draft.tags} onChange={(event) => change('tags', event.target.value)} /></label>
        <label>Expiry date<input type="date" value={draft.expiry_date} onChange={(event) =>
          change('expiry_date', event.target.value)} /></label>
      </div>
      <label className="checkbox"><input type="checkbox" checked={draft.favorite}
        onChange={(event) => change('favorite', event.target.checked)} /> Favorite</label>
      {oversized && <p className="error" role="alert">A field exceeds the configured size limit.</p>}
      {!parsed.success && dirty && <p className="muted">Enter a credential name and complete or remove each field.</p>}
      {error && <p className="error" role="alert">{error}</p>}
      <div className="actions">
        <button className="primary" type="submit" disabled={!valid || saving}>Save credential</button>
        <button className="secondary" type="button" disabled={saving} onClick={() => {
          if (!dirty || window.confirm('Discard unsaved changes?')) close()
        }}>Cancel</button>
      </div>
    </form>
  )
}
