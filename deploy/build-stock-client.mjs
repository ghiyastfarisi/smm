// Builds the unmodified Mattermost web app (release 1.0.0-rc.1 serves it at /) and copies it, without source maps, to
// server/client, which deploy/server.Dockerfile bundles into the server image.
// Usage: node deploy/build-stock-client.mjs [--skip-build]   then: cd deploy && docker compose up -d --build server
import { execFileSync } from 'node:child_process'
import { cpSync, rmSync, mkdirSync, readdirSync, statSync, existsSync } from 'node:fs'
import { join } from 'node:path'

const root = new URL('../', import.meta.url).pathname
const webapp = join(root, 'webapp')
const src = join(webapp, 'channels/dist')
const dst = join(root, 'server/client')

if (!process.argv.includes('--skip-build')) {
  // The upstream package pins an exact Node version; any Node 24 works, so the engine check is relaxed.
  execFileSync('npm', ['ci', '--no-audit', '--no-fund', '--engine-strict=false'], { cwd: webapp, stdio: 'inherit' })
  execFileSync('npm', ['run', 'build'], { cwd: webapp, stdio: 'inherit' })
}
if (!existsSync(join(src, 'root.html'))) throw new Error(`no build output at ${src}`)
rmSync(dst, { recursive: true, force: true })
mkdirSync(dst, { recursive: true })
cpSync(src, dst, { recursive: true, filter: p => !p.endsWith('.map') }) // no source maps in the image (SEC-09)
let n = 0, bytes = 0
const walk = d => { for (const f of readdirSync(d)) { const p = join(d, f); const s = statSync(p); if (s.isDirectory()) walk(p); else { n++; bytes += s.size } } }
walk(dst)
console.log(`client: ${n} files, ${(bytes / 1e6).toFixed(0)} MB → ${dst}`)
