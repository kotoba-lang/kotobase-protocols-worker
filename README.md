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

## Auth (writes only; reads are public, fail-closed otherwise)

A write (PUT/POST/DELETE) is accepted if **either** credential verifies:

- **Bearer** — `authorization: Bearer <WRITE_TOKEN>`.
- **AWS SigV4** — `authorization: AWS4-HMAC-SHA256 …` verified against
  `S3_ACCESS_KEY_ID` / `S3_SECRET_ACCESS_KEY` over the raw payload
  (`curl --aws-sigv4 "aws:amz:auto:s3" --user "$AKID:$SECRET"` or any
  aws-sdk S3 client pointed at `s3.kotobase.net`).

All three are Worker secrets; operator copies are in the macOS Keychain,
service `cf:kotobase-protocols-worker` (accounts `WRITE_TOKEN`,
`S3_ACCESS_KEY_ID`, `S3_SECRET_ACCESS_KEY`) — reference only, see the
superproject `secrets-location-map` skill (ADR-2607176000).

## Content addressing

`POST /ipfs` with a raw body mints a **real CIDv1** (`sha2-256`, codec
`raw`, base32 `bafkrei…`) and stores the bytes; `GET /ipfs/{cid}` serves
them back. The CID matches what any IPFS tool computes for the same
bytes.

## Seeding a git repo

`bin/seed_git.cljs` pushes a local repo's loose objects, refs and HEAD
into the git surface so it clones over dumb-HTTP:

```bash
KOTOBASE_WRITE_TOKEN=$TOKEN nbb bin/seed_git.cljs \
  <local-repo> kotoba-lang/<name> https://git.kotobase.net
git clone https://git.kotobase.net/kotoba-lang/<name>
```

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
