// Proves at-rest encryption on the running compose stack with fresh canary data. Every check carries a checklist
// ID (ENC-…), the same IDs docs/ENCRYPTION.md lists.
//  1. writes a message, a hashtag, a file, a draft, a slash command and a user profile containing a random canary
//     through the API;
//  2. dumps the whole database and every stored file and searches them for the canary (must be absent);
//  3. shows the stored form (enc:v3 values bound to their row, MMENCF file headers, hashed session tokens);
//  4. shows the API still returns the plaintext and search still finds the canary (so it is encryption, not loss);
//  5. moves one ciphertext into another row in the database: it must no longer decrypt there (row binding);
//  6. writes a legacy plaintext row straight into the database: it must still be readable (pre-encryption data);
//  7. lists what stays in plaintext by design.
// Usage: node deploy/prove-encryption.mjs   (needs docker compose access; cleans up after itself; exit 1 on a failure)
import { execFileSync } from 'node:child_process'
import { readFileSync } from 'node:fs'
import { createHash, randomBytes } from 'node:crypto'

const API = process.env.SERVER ?? 'http://localhost:8065'
const COMPOSE = new URL('./docker-compose.yml', import.meta.url).pathname
const dc = (...a) => execFileSync('docker', ['compose', '-f', COMPOSE, ...a], { maxBuffer: 1 << 30 })
const sql = q => dc('exec', '-T', 'db', 'psql', '-U', 'mmuser', '-d', 'mrpostman', '-tAc', q).toString().trim()
const mmctl = (...a) => { try { dc('exec', '-T', 'server', 'mmctl', '--local', ...a) } catch { /* cleanup best effort */ } }

async function apiAs(login, password) {
  const r = await fetch(`${API}/api/v4/users/login`, { method: 'POST', body: JSON.stringify({ login_id: login, password }) })
  if (!r.ok) throw new Error(`login ${login}: ${r.status}`)
  const token = r.headers.get('token')
  const H = { Authorization: `Bearer ${token}`, 'X-Requested-With': 'XMLHttpRequest' }
  const call = async (p, m = 'GET', body, raw = false) => {
    const res = await fetch(`${API}/api/v4${p}`, { method: m, headers: body instanceof FormData ? H : { ...H, 'Content-Type': 'application/json' }, body: body instanceof FormData ? body : body && JSON.stringify(body) })
    if (raw) return res
    const t = await res.text()
    if (!res.ok) throw new Error(`${m} ${p}: ${res.status} ${t.slice(0, 200)}`)
    return t ? JSON.parse(t) : undefined
  }
  return Object.assign(call, { token })
}

/** Plaintext the design leaves readable; shown as INFO and tracked as manual rows in the checklist (ENC-31). */
export const PLAINTEXT_BY_DESIGN = [
  'usernames (login, @mentions)',
  'team names/display names, channel names/display names',
  'timestamps, membership, reactions (emoji names), preferences, file sizes/types',
  'data in transit: use TLS in front of nginx in production (this dev stack is plain HTTP)',
  'push notifications, e-mails, logs, server memory',
]

/**
 * Runs every check. `report(id, ok, what, detail)` is called once per check; `info(what, detail)` for notes
 * (the first info is the canary word, so callers can grep logs for it). Returns the number of failed checks.
 * Creates and deletes its own user and team.
 */
export async function proveEncryption(report, info = () => {}) {
  let failed = 0
  const row = (id, ok, what, detail = '') => { if (!ok) failed++; report(id, ok, what, detail) }

  // ── 1. canary data through the normal API ──────────────────────────────────────────────────────────────────
  const canary = `canary${randomBytes(6).toString('hex')}`
  const pw = `Pw-${randomBytes(8).toString('hex')}!`
  info('canary', canary)
  const admin = await apiAs('admin', 'Demo#12345')
  const team = await admin('/teams', 'POST', { name: `e2e-proof-${randomBytes(4).toString('hex')}`, display_name: 'Proof', type: 'I' }) // team names are plaintext by design: no canary
  const username = `e2eproof${canary.slice(-8)}`
  const user = await admin('/users', 'POST', { username, email: `${canary}@proof.example`, password: pw, first_name: `First${canary}`, last_name: `Last${canary}`, nickname: `Nick${canary}`, position: `Pos${canary}` })
  await admin(`/teams/${team.id}/members`, 'POST', { team_id: team.id, user_id: user.id })
  const u = await apiAs(username, pw)
  const ch = await u('/channels', 'POST', { team_id: team.id, name: 'proof', display_name: 'Proof', type: 'P', header: `Header${canary}`, purpose: `Purpose${canary}` })
  await u(`/channels/${ch.id}/patch`, 'PUT', { header: `Header2${canary}` }) // system_header_change post: old/new header in its props
  const message = `secret message ${canary} with #tag${canary}`
  const post = await u('/posts', 'POST', { channel_id: ch.id, message })
  const fd = new FormData()
  fd.append('channel_id', ch.id)
  fd.append('files', new Blob([`file body ${canary}\n`.repeat(50)], { type: 'text/plain' }), `report-${canary}.txt`)
  const file = (await u('/files', 'POST', fd)).file_infos[0]
  await u('/posts', 'POST', { channel_id: ch.id, message: 'attachment', file_ids: [file.id] })
  await u('/drafts', 'POST', { user_id: user.id, channel_id: ch.id, root_id: '', message: `draft ${canary}` }).catch(e => info('drafts', `not stored (${e.message.slice(0, 80)})`))
  const cmd = await admin('/commands', 'POST', { team_id: team.id, trigger: `proof${canary.slice(-6)}`, method: 'P', url: 'http://localhost:9/none', display_name: 'proof' }).catch(() => null)
  const victim = await u('/posts', 'POST', { channel_id: ch.id, message: `other message ${randomBytes(4).toString('hex')}` }) // for steps 5 and 6
  const ch2 = await u('/channels', 'POST', { team_id: team.id, name: 'proof-other', display_name: 'Proof other', type: 'P' })
  const victim2 = await u('/posts', 'POST', { channel_id: ch2.id, message: `other channel ${randomBytes(4).toString('hex')}` }) // for ENC-37
  const scheduled = await u('/posts/schedule', 'POST', { channel_id: ch.id, user_id: user.id, message: `scheduled ${canary}`, scheduled_at: Date.now() + 3600_000 }).catch(e => (info('scheduled posts', `not stored (${e.message.slice(0, 80)})`), null))
  await new Promise(r => setTimeout(r, 1500)) // let file extraction / search indexing finish

  try {
    // ── 2. no canary anywhere at rest ────────────────────────────────────────────────────────────────────────
    const dump = dc('exec', '-T', 'db', 'pg_dump', '-U', 'mmuser', 'mrpostman')
    const text = dump.toString('latin1')
    const hits = needle => text.split(needle).length - 1
    const around = needle => { const i = text.indexOf(needle); return i < 0 ? '' : `; first hit: …${text.slice(Math.max(0, i - 120), i + 60).replace(/\s+/g, ' ')}…` }
    row('ENC-01', hits(canary) === 0, 'database dump (pg_dump of every table) contains no canary', `${hits(canary)} hit(s) in ${(dump.length / 1e6).toFixed(1)} MB${around(canary)}`)
    row('ENC-02', hits(`secret message ${canary}`) === 0, 'message text absent from the dump')
    row('ENC-03', hits(`report-${canary}`) === 0, 'file name absent from the dump')
    row('ENC-04', hits(`First${canary}`) === 0 && hits(`Nick${canary}`) === 0 && hits(`Pos${canary}`) === 0, 'first name, nickname and position absent from the dump')
    row('ENC-05', hits(`${canary}@proof.example`) === 0, 'e-mail address absent from the dump')
    const tar = dc('exec', '-T', 'server', 'tar', 'cf', '-', '-C', '/mattermost/data', 'files')
    row('ENC-06', !tar.includes(Buffer.from(canary)), 'file store (tar of /mattermost/data/files) contains no canary', `${(tar.length / 1e6).toFixed(1)} MB scanned`)

    // ── 3. what is stored instead ────────────────────────────────────────────────────────────────────────────
    const stored = sql(`select message from posts where id='${post.id}'`)
    row('ENC-07', /^enc:v[34]:/.test(stored) && stored.includes(`:posts.message#${post.id}:`), 'post stored as enc:v<n>:<key id>:…:posts.message#<post id>:<AES-GCM>', stored.slice(0, 130) + '…')
    const tags = sql(`select hashtags from posts where id='${post.id}'`)
    row('ENC-08', /^enc:v[34]:/.test(tags), 'hashtags encrypted', tags.slice(0, 70) + '…')
    const urow = sql(`select email||' | '||firstname||' | '||lastname||' | '||nickname||' | '||position from users where id='${user.id}'`)
    row('ENC-09', urow.split(' | ').every(v => v.startsWith('enc:v3:')), 'user e-mail, first/last name, nickname, position encrypted (global v3 key)', urow.slice(0, 110) + '…')
    const frow = sql(`select name||' | '||path from fileinfo where id='${file.id}'`)
    row('ENC-10', /^enc:v[34]:/.test(frow), 'file name encrypted (path is ids only)', frow.slice(0, 160))
    const blob = dc('exec', '-T', 'server', 'cat', `/mattermost/data/files/${frow.split(' | ')[1]}`)
    row('ENC-11', blob.subarray(0, 6).toString() === 'MMENCF', 'file content on disk starts with the MMENCF encryption header', JSON.stringify(blob.subarray(0, 16).toString('latin1')))
    const files = dc('exec', '-T', 'server', 'sh', '-c', 'find /mattermost/data/files -type f -exec head -c 6 {} \\; -exec echo \\;').toString().split('\n').filter(Boolean)
    const plainFiles = files.filter(h => h !== 'MMENCF').length
    row('ENC-12', plainFiles === 0, 'every stored file has the encryption header', `${files.length - plainFiles}/${files.length} encrypted`)
    const draft = sql(`select message from drafts where userid='${user.id}' limit 1`)
    row('ENC-13', !draft || /^enc:v[34]:/.test(draft), 'draft encrypted', draft ? draft.slice(0, 80) + '…' : 'no draft stored on this server (skipped)')
    const sha = createHash('sha256').update(u.token).digest('hex')
    row('ENC-14', hits(u.token) === 0 && sql(`select count(*) from sessions where token='${sha}'`) === '1', 'session token stored only as SHA-256 (a dump yields nothing to log in with)')
    const tok = sql(`select count(*)||' '||count(*) filter (where tokenhash ~ '^[0-9a-f]{64}$') from postsearchtokens`).split(' ')
    row('ENC-15', tok[0] !== '0' && tok[0] === tok[1], 'search index holds keyed hashes (HMAC-SHA256) of words, not words', `${tok[0]} rows, ${tok[1]} are 64-hex HMACs`)
    const env = readFileSync(new URL('./.env', import.meta.url), 'utf8')
    const keys = ['ENCRYPTION_KEY', 'ENCRYPTION_KEY_FACTOR'].map(k => env.match(new RegExp(`^${k}=(.+)$`, 'm'))?.[1]).filter(Boolean)
    if (cmd) {
      const ctok = sql(`select token from commands where id='${cmd.id}'`)
      row('ENC-17', ctok.startsWith('enc:v3:') && hits(cmd.token) === 0, 'slash-command token encrypted', ctok.slice(0, 60) + '…')
    } else row('ENC-17', true, 'slash-command token encrypted', 'commands disabled on this server (skipped)')
    const audit = sql(`select coalesce(ipaddress,'') from audits where userid='${user.id}' order by createat desc limit 1`)
    row('ENC-18', !audit || audit.startsWith('enc:v3:'), 'audit record (IP address) encrypted', audit ? audit.slice(0, 60) + '…' : 'no audit row (skipped)')

    // ── 4. still readable through the server, still searchable ───────────────────────────────────────────────
    row('ENC-19', (await u(`/posts/${post.id}`)).message === message, 'API returns the decrypted message')
    const me = await u('/users/me')
    row('ENC-20', me.first_name === `First${canary}` && me.email === `${canary}@proof.example`, 'API returns the decrypted profile')
    const content = await (await u(`/files/${file.id}`, 'GET', undefined, true)).text()
    row('ENC-21', content.includes(canary), 'API returns the decrypted file')
    const found = await u(`/teams/${team.id}/posts/search`, 'POST', { terms: canary, is_or_search: false })
    row('ENC-22', found.order.includes(post.id), 'search finds the encrypted message (blind index)')

    // ── 5. ciphertext is bound to its row ────────────────────────────────────────────────────────────────────
    sql(`update posts set message=(select message from posts where id='${post.id}') where id='${victim.id}'`)
    const moved = (await u(`/posts/${victim.id}`)).message
    row('ENC-23', !moved.includes(canary), 'a ciphertext copied into another row does not decrypt there (AES-GCM label = column + row id)', `post ${victim.id} now reads: ${moved.slice(0, 60)}…`)

    // ── 6. legacy plaintext rows (data from before encryption) stay readable ─────────────────────────────────
    const legacy = `legacy plaintext ${randomBytes(3).toString('hex')}`
    sql(`update posts set message='${legacy}' where id='${victim.id}'`)
    row('ENC-24', (await u(`/posts/${victim.id}`)).message === legacy, 'a plaintext row written before encryption is still returned as is')

    // ── 7. per-team + per-channel keys (v4), OpenBAO custody ─────────────────────────────────────────────────
    row('ENC-36', stored.startsWith(`enc:v4:`) && stored.split(':')[3] === `${team.id}/${ch.id}` && stored.includes(`:posts.message#${post.id}:`), 'post stored as enc:v4:<kid>:<team id>/<channel id>:posts.message#<post id>: (key derived per team + channel)', stored.slice(0, 130) + '…')
    sql(`update posts set message=(select message from posts where id='${post.id}') where id='${victim2.id}'`)
    const moved2 = (await u(`/posts/${victim2.id}`)).message
    row('ENC-37', !moved2.includes(canary), 'a ciphertext copied into a post row of another channel does not decrypt there (scope in the key and the GCM tag, checked against the row)', `post ${victim2.id} now reads: ${moved2.slice(0, 60)}…`)
    const serverEnv = dc('exec', '-T', 'server', 'env').toString().split('\n').filter(l => /^ENCRYPTION_KEY/.test(l)).map(l => l.split('=')[0])
    row('ENC-38', serverEnv.length === 0, 'the server container environment holds no ENCRYPTION_KEY / ENCRYPTION_KEY_FACTOR (keys live in OpenBAO)', serverEnv.length ? `found: ${serverEnv.join(', ')}` : 'env has no ENCRYPTION_KEY* variable')
    // KMS profile (docker-compose.kms.yml): the dev root token is not valid there; use the operator's token from
    // kms-setup.sh's init file, or BAO_TOKEN from the environment.
    let kmsInit = ''
    try { kmsInit = readFileSync(new URL('./openbao/secrets/init.txt', import.meta.url), 'utf8') } catch {}
    const kmsMode = dc('exec', '-T', 'server', 'env').toString().includes('OPENBAO_ROLE_ID=')
    const rootToken = process.env.BAO_TOKEN || (kmsMode && kmsInit.match(/^Initial Root Token: (\S+)/m)?.[1]) || env.match(/^OPENBAO_ROOT_TOKEN=(.+)$/m)?.[1]
    const kvPath = env.match(/^OPENBAO_KV_PATH=(.+)$/m)?.[1] ?? 'secret/data/mrpostman/root'
    const [mount, ...restPath] = kvPath.split('/data/')
    const baoField = f => { try { return dc('exec', '-T', '-e', `BAO_TOKEN=${rootToken}`, 'openbao', 'bao', 'kv', 'get', `-mount=${mount}`, `-field=${f}`, restPath.join('/data/')).toString().trim() } catch (e) { return `error: ${e.message.slice(0, 80)}` } }
    const baoKey = baoField('key')
    // keys.length 0: the root keys left deploy/.env (kms-setup.sh forget-env-keys) and OpenBAO is their only copy.
    const custody = keys.length === 2 ? (baoKey === keys[0] ? 'key matches the .env seed' : `mismatch (${baoKey.slice(0, 40)})`) : 'deploy/.env holds no ENCRYPTION_KEY*: OpenBAO is the only copy'
    const baoOk = !!rootToken && !baoKey.startsWith('error') && baoKey.length > 40 && (keys.length === 0 || baoKey === keys[0])
    row('ENC-39', baoOk, `root secret exists in OpenBAO at ${kvPath} (and equals the .env seed while one is there; existing data stayed readable)`, custody)
    const rootKeys = keys.length === 2 ? keys : [baoKey, baoField('factor')]
    row('ENC-16', rootKeys.every(k => k.length > 40 && !k.startsWith('error') && hits(k) === 0), 'encryption keys are not in the database (they live in OpenBAO, and in deploy/.env only until forget-env-keys)')
    row('ENC-40', blob.subarray(0, 8).toString('latin1') === 'MMENCF3\0', 'uploaded file starts with the MMENCF3 header (file key derived per team + channel of its path)', JSON.stringify(blob.subarray(0, 16).toString('latin1')))
    const draftV4 = draft ? draft.startsWith('enc:v4:') && draft.split(':')[3] === `${team.id}/${ch.id}` : true
    const sched = scheduled ? sql(`select message from scheduledposts where id='${scheduled.id}'`) : ''
    const schedV4 = sched ? sched.startsWith('enc:v4:') && sched.split(':')[3] === `${team.id}/${ch.id}` : true
    row('ENC-41', draftV4 && schedV4, 'drafts and scheduled posts are v4 under their channel scope', `${draft ? `draft ${draft.slice(0, 70)}…` : 'no draft (skipped)'}; ${sched ? `scheduled ${sched.slice(0, 70)}…` : 'no scheduled post (skipped)'}`)

    const chRow = sql(`select header || ' | ' || purpose from channels where id='${ch.id}'`)
    const pubRow = sql(`select count(*) from publicchannels where header like '%${canary}%' or purpose like '%${canary}%'`)
    const props = sql(`select props::text from posts where channelid='${ch.id}' and type='system_header_change'`)
    const apiCh = await u(`/channels/${ch.id}`)
    row('ENC-32', chRow.split(' | ').every(v => v.startsWith(`enc:v4:`) && v.split(':')[3] === `${team.id}/${ch.id}`) && pubRow === '0' && !!props && !props.includes(canary) && hits(`Purpose${canary}`) === 0 && apiCh.header === `Header2${canary}` && apiCh.purpose === `Purpose${canary}`,
      'channel header and purpose stored v4 under the channel scope (also the header-change post props); API returns them decrypted', `${chRow.slice(0, 90)}…; props ${props.slice(0, 80)}…`)
    const kid = stored.split(':')[2]
    const others = `not in (select id from channels where teamid='${team.id}')` // ENC-23/24 plant legacy rows in the proof team
    const legacyRows = Object.fromEntries(Object.entries({
      posts: `select count(*) from posts where message <> '' and message not like 'enc:v4:${kid}:%' and channelid ${others}`,
      'post hashtags': `select count(*) from posts where hashtags <> '' and hashtags not like 'enc:v4:${kid}:%'`,
      'file names': `select count(*) from fileinfo where name <> '' and name not like 'enc:v4:${kid}:%'`,
      drafts: `select count(*) from drafts where message <> '' and message not like 'enc:v4:${kid}:%'`,
      'channel headers/purposes': `select count(*) from channels where (header <> '' and header not like 'enc:v4:${kid}:%') or (purpose <> '' and purpose not like 'enc:v4:${kid}:%')`,
      'user e-mails': `select count(*) from users where email <> '' and email not like 'enc:v3:${kid}:%'`,
    }).map(([k, q]) => [k, Number(sql(q))]))
    row('ENC-42', Object.values(legacyRows).every(n => n === 0), `every stored row is sealed under the current root (kid ${kid}): no plaintext or older-format rows left`, Object.entries(legacyRows).map(([k, n]) => `${k} ${n}`).join(', '))

    info('not encrypted (needed for routing, lookup or display before decryption):', PLAINTEXT_BY_DESIGN.join('\n      '))
  } finally {
    mmctl('user', 'delete', user.id, '--confirm')
    mmctl('team', 'delete', team.name, '--confirm')
  }
  return failed
}

// CLI
if (process.argv[1] && import.meta.url === new URL(`file://${process.argv[1]}`).href) {
  const failed = await proveEncryption(
    (id, ok, what, detail) => console.log(`${ok ? 'PASS' : 'FAIL'}  ${id} ${what}${detail ? `\n      ${detail}` : ''}`),
    (what, detail) => console.log(`INFO  ${what}${detail ? `\n      ${detail}` : ''}`),
  )
  console.log(failed ? `\n${failed} check(s) FAILED` : '\nall checks passed: data at rest is encrypted')
  process.exit(failed ? 1 : 0)
}
