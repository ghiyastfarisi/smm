// Compliance export and data retention for SMM 1.0.0: the open-source substitutes for Mattermost's
// licensed Compliance Export and Data Retention. Both go through the API as
// a system admin, because the database holds only ciphertext (an SQL export would contain nothing readable).
//
//   MM_TOKEN=<system admin personal access token> node deploy/records.mjs export --since 2026-10-01 [--until 2026-10-31]
//            [--user <username>] [--keyword <word>] > export.csv
//   MM_TOKEN=... node deploy/records.mjs retention --days 365            dry run: counts what would be deleted
//   MM_TOKEN=... node deploy/records.mjs retention --days 365 --apply    permanently deletes posts (and their files)
//
// SERVER defaults to http://localhost:8065. Every channel is covered, DMs and group messages included (found through
// each user's channel list). Retention needs ServiceSettings.EnableAPIPostDeletion; the script switches it on for the
// run and restores the previous value. Pinned posts are kept unless --include-pinned.
// ponytail: walks every post through the API (O(posts)); fine for a single organisation's size, move to a server job if it gets slow.
const API = `${process.env.SERVER ?? 'http://localhost:8065'}/api/v4`
const TOKEN = process.env.MM_TOKEN
const [cmd, ...rest] = process.argv.slice(2)
const opt = Object.fromEntries(rest.reduce((a, x, i, all) => (x.startsWith('--') && a.push([x.slice(2), all[i + 1]?.startsWith('--') || all[i + 1] === undefined ? true : all[i + 1]]), a), []))

async function api(path, method = 'GET', body) {
  let r
  // The release profile rate-limits the API (CFG-01); wait out a 429 instead of failing a long export.
  for (let tries = 0; ; tries++) {
    r = await fetch(API + path, { method, headers: { Authorization: `Bearer ${TOKEN}`, 'Content-Type': 'application/json', 'X-Requested-With': 'XMLHttpRequest' }, body: body && JSON.stringify(body) })
    if (r.status !== 429 || tries >= 30) break
    await r.arrayBuffer()
    const wait = Number(r.headers.get('retry-after') ?? r.headers.get('x-ratelimit-reset') ?? 1)
    await new Promise(res => setTimeout(res, Math.min(Math.max(wait, 1), 10) * 1000))
  }
  const t = await r.text()
  if (!r.ok) throw new Error(`${method} ${path}: ${r.status} ${t.slice(0, 200)}`)
  return t ? JSON.parse(t) : undefined
}
async function* pages(path, per = 200) {
  for (let page = 0; ; page++) {
    const sep = path.includes('?') ? '&' : '?'
    const batch = await api(`${path}${sep}page=${page}&per_page=${per}`)
    const items = Array.isArray(batch) ? batch : batch.order.map(id => batch.posts[id])
    yield* items
    if (items.length < per) return
  }
}
const day = s => { const t = Date.parse(s); if (Number.isNaN(t)) throw new Error(`bad date ${s}`); return t }

/** Every channel on the server, DMs/GMs included, with team names for the export. */
async function allChannels() {
  const users = new Map(), channels = new Map(), teams = new Map()
  for await (const t of pages('/teams')) teams.set(t.id, t.name)
  for await (const u of pages('/users?include_deleted=true')) users.set(u.id, u.username)
  for (const id of users.keys()) {
    const mine = await api(`/users/${id}/channels?include_deleted=true`).catch(e => { if (/ 404 /.test(e.message)) return []; throw e }) // 404 = no channels
    for (const c of mine) channels.set(c.id, c)
  }
  return { users, teams, channels: [...channels.values()] }
}

async function exportPosts() {
  if (!opt.since) throw new Error('export needs --since YYYY-MM-DD')
  const since = day(opt.since), until = opt.until ? day(opt.until) + 86400_000 : Infinity
  const { users, teams, channels } = await allChannels()
  const userId = opt.user && [...users].find(([, n]) => n === opt.user)?.[0]
  if (opt.user && !userId) throw new Error(`no user ${opt.user}`)
  const kw = typeof opt.keyword === 'string' ? opt.keyword.toLowerCase() : ''
  const csv = v => `"${String(v ?? '').replaceAll('"', '""')}"`
  console.log(['created_at', 'team', 'channel', 'channel_type', 'user', 'post_id', 'root_id', 'edited', 'deleted', 'message', 'files'].join(','))
  let n = 0
  for (const c of channels) {
    for await (const p of pages(`/channels/${c.id}/posts?include_deleted=true`)) {
      if (p.create_at < since) break // newest first
      if (p.create_at >= until || (userId && p.user_id !== userId) || (kw && !p.message.toLowerCase().includes(kw))) continue
      console.log([new Date(p.create_at).toISOString(), teams.get(c.team_id) ?? '', c.name, c.type, users.get(p.user_id) ?? p.user_id, p.id, p.root_id,
        p.edit_at ? new Date(p.edit_at).toISOString() : '', p.delete_at ? new Date(p.delete_at).toISOString() : '', p.message,
        (p.metadata?.files ?? []).map(f => f.name).join(' ')].map(csv).join(','))
      n++
    }
  }
  console.error(`exported ${n} post(s) from ${channels.length} channel(s)`)
}

async function retention() {
  const days = Number(opt.days)
  if (!(days >= 1)) throw new Error('retention needs --days N (N >= 1)')
  const cutoff = Date.now() - days * 86400_000
  const { channels } = await allChannels()
  const old = []
  for (const c of channels) {
    for await (const p of pages(`/channels/${c.id}/posts`)) {
      if (p.create_at < cutoff && (opt['include-pinned'] || !p.is_pinned)) old.push(p.id)
    }
  }
  console.error(`${old.length} post(s) older than ${days} day(s) (before ${new Date(cutoff).toISOString()}) in ${channels.length} channel(s)`)
  if (!opt.apply) return console.error('dry run: add --apply to delete them permanently')
  const cfg = await api('/config')
  const prev = cfg.ServiceSettings.EnableAPIPostDeletion
  await api('/config/patch', 'PUT', { ServiceSettings: { EnableAPIPostDeletion: true } })
  try {
    for (const id of old) await api(`/posts/${id}?permanent=true`, 'DELETE').catch(e => { if (!/404/.test(e.message)) throw e }) // replies go with their root
  } finally {
    await api('/config/patch', 'PUT', { ServiceSettings: { EnableAPIPostDeletion: prev } })
  }
  console.error(`deleted ${old.length} post(s)`)
}

if (!TOKEN) { console.error('set MM_TOKEN to a system admin personal access token'); process.exit(2) }
const run = { export: exportPosts, retention }[cmd]
if (!run) { console.error('usage: node deploy/records.mjs export|retention … (see the header of this file)'); process.exit(2) }
await run()
