export function residentialCandidates(rows) {
  return (rows || [])
    .filter((row) => ['residential_candidate', 'mobile'].includes(String(row?.network_type || '').toLowerCase()))
    .map((row) => ({ ...row, asn: String(row.asn || '').trim().toUpperCase() }))
    .filter((row) => row.asn)
}

export function enabledAsns(rows) {
  return (rows || [])
    .filter((row) => row && row.enabled !== false)
    .map((row) => String(row.asn || '').trim().toUpperCase())
    .filter(Boolean)
}

export function attachAsnAssignments(emails, asns) {
  const active = (asns || []).filter(Boolean)
  if (!active.length) return []
  return (emails || []).map((email, index) => ({ email, asn: active[index % active.length] }))
}
