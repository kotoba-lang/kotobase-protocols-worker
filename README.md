# kotobase-protocols-worker

[![CI](https://github.com/kotoba-lang/kotobase-protocols-worker/actions/workflows/ci.yml/badge.svg)](https://github.com/kotoba-lang/kotobase-protocols-worker/actions/workflows/ci.yml)

Cloudflare Worker **deploy shell** for
[kotoba-lang/kotobase-protocols](https://github.com/kotoba-lang/kotobase-protocols)
(ADR-2607174500 in `com-junkawasaki/root`). Serves, live:

| Host | Surface |
|---|---|
| `s3.kotobase.net` | S3 object API |
| `atproto.kotobase.net` | AT-Proto XRPC tenant data-plane |
| `git.kotobase.net` | git dumb-HTTP (read) |
| `kotobase-protocols-worker.*.workers.dev` | all of the above via `/s3/*`, `/xrpc/*`, `/git/*`, `/ipfs/*` |

`ipfs.kotobase.net` is deliberately **not** routed here — that hostname is
owned by `gftdcojp/net-kotobase-ipfs` (ADR-2607072000).

## How it persists (v0, read the limits)

The whole `kotobase.store/IStore` state lives in **one R2 object**
(`kotobase-protocols/state.edn`, EDN via `pr-str`/`read-string`):

1. hydrate → seed a `kotobase.local/LocalStore` (atom owned by the shell)
2. run the pure `kotobase.protocols.router` synchronously
3. writes: persist the snapshot back with `onlyIf: {etagMatches}` —
   optimistic lock, up to 3 attempts, then `503`.

This keeps the handlers 100% synchronous and pure at the cost of
single-object scale: state must fit in memory, and write throughput is
one-writer-at-a-time. That is the declared v0 trade-off; per-collection
sharding / Durable Objects / the real kotobase datom plane are follow-ups.

## Auth

Reads are public. **Writes require `authorization: Bearer <WRITE_TOKEN>`**
and fail closed (401) when the secret is unset. The token lives in the
Worker secret `WRITE_TOKEN`; the operator copy is in the macOS Keychain,
service `cf:kotobase-protocols-worker`, account `WRITE_TOKEN` (reference
only — see the superproject `secrets-location-map` skill).

## Develop

```bash
# tests (pure logic; nbb is the first-class runtime)
nbb --classpath "src:test:../kotobase-protocols/src:../kotobase/src" bin/run_tests.cljs

# build (in the superproject, go through the resource governor)
npx shadow-cljs release worker     # → out/worker.js (:esm)

# deploy
npx wrangler deploy
printf '%s' "$TOKEN" | npx wrangler secret put WRITE_TOKEN
```

Library deps are shadow `:source-paths` to the sibling west checkouts
(`../kotobase-protocols`, `../kotobase`), the same pattern as
`kotobase-cljc-worker`.

## License

Apache-2.0
