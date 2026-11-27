export const characterGroups = {
  Uppercase: 'ABCDEFGHIJKLMNOPQRSTUVWXYZ',
  Lowercase: 'abcdefghijklmnopqrstuvwxyz',
  Numbers: '0123456789',
  Symbols: '!@#$%^&*+-=_?',
} as const

export type PasswordGroup = keyof typeof characterGroups
export const defaults = Object.keys(characterGroups) as PasswordGroup[]

function pick(size: number) {
  const sample = new Uint32Array(1)
  const ceiling = 2 ** 32 - (2 ** 32 % size)
  do { crypto.getRandomValues(sample) } while (sample[0]! >= ceiling)
  return sample[0]! % size
}

export function generatePassword(length = 24, selected = defaults, excludeAmbiguous = false) {
  if (!Number.isInteger(length) || length < 8 || length > 128 || selected.length === 0) {
    throw new Error('Choose a length between 8 and 128 and at least one character group.')
  }
  const groups = selected.map((group) => excludeAmbiguous ? characterGroups[group].replace(/[0O1lI]/g, '')
    : characterGroups[group])
  const alphabet = groups.join('')
  let proposal: string
  do {
    proposal = Array.from({ length }, () => alphabet[pick(alphabet.length)]!).join('')
  } while (groups.some((group) => !Array.from(proposal).some((character) => group.includes(character))))
  return proposal
}

export async function generatePassphrase(count: number) {
  if (!Number.isInteger(count) || count < 6 || count > 12) throw new Error('Choose six to twelve words.')
  const { default: list } = await import('./eff-words.txt?raw')
  const words = list.trim().split(/\r?\n/)
  if (words.length !== 7776 || new Set(words).size !== 7776) throw new Error('Word list is unavailable.')
  return Array.from({ length: count }, () => words[pick(words.length)]!).join(' ')
}
