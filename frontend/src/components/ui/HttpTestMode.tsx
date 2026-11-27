import { useId, useState } from 'react'

export function HttpTestMode() {
  const tooltipId = useId()
  const [dismissed, setDismissed] = useState(false)

  if (window.location.protocol !== 'http:') return null

  return <span className="http-test-mode" tabIndex={0} aria-describedby={tooltipId}
    data-dismissed={dismissed || undefined} onBlur={() => setDismissed(false)}
    onPointerLeave={() => setDismissed(false)}
    onKeyDown={(event) => { if (event.key === 'Escape') setDismissed(true) }}>
    HTTP Test Mode
    <span className="http-test-mode-tooltip" id={tooltipId} role="tooltip">
      Traffic is unencrypted. Use only dummy credentials.
    </span>
  </span>
}
