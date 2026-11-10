export function analyzeTokenExport(text = '') {
  const lines = String(text).split('\n').map((line) => line.trim())
  const nonempty = lines.filter(Boolean)
  const unique = new Set(nonempty).size
  return {
    total: lines.length,
    nonempty: nonempty.length,
    unique,
    duplicates: nonempty.length - unique,
  }
}
