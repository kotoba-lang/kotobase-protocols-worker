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
| `pinning.kotobase.net` | [IPFS Pinning Service API](https://ipfs.github.io/pinning-services-api-spec/) |
| `kotobase-protocols-worker.*.workers.dev` | all of the above via `/s3/*`, `/xrpc/*`, `/git/*`, `/ipfs/*`, `/pins*` |

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

A write (PUT/POST/DELETE) is accepted if **any** credential verifies:

- **Bearer** — `authorization: Bearer <WRITE_TOKEN>`. Full admin, every surface.
- **AWS SigV4** — `authorization: AWS4-HMAC-SHA256 …` verified against
  `S3_ACCESS_KEY_ID` / `S3_SECRET_ACCESS_KEY` over the raw payload
  (`curl --aws-sigv4 "aws:amz:auto:s3" --user "$AKID:$SECRET"` or any
  aws-sdk S3 client pointed at `s3.kotobase.net`). Full admin, every surface
  (not S3-scoped in this worker — see ADR-2607177000 for the honest note).
- **CACAO** — `{"cacao_b64": "…"}` in the JSON body, or
  `authorization: CACAO <b64>` (ADR-2607177000). Verified byte-exact against
  what `kotobase.net`'s own edge (`kotobase-cljc-worker`) checks: Ed25519
  signature over the CACAO's SIWE message, under the `did:key` in its `iss`.
  What it then authorizes is **per-surface**, not universal:
  - **atproto**: a valid CACAO authorizes a write **only when its issuer DID
    equals the request's `repo` field** — you can write your own AT-Proto
    records with nothing but your own keypair, no shared secret needed.
    There is no "wrong DID" case to reject — a mismatched `repo` is simply
    not your graph, structurally, the same principle
    `kotobase-cljc-worker` uses to derive `canonical-graph(issuer, db_name)`.
  - **s3 / git / pinning**: these surfaces have no DID-shaped resource
    identity yet (a bucket, a git repo, a pin request are just opaque
    strings, owned by nobody in particular). A valid CACAO here is honored
    only when its issuer is in `CACAO_OPERATOR_DIDS` (a CSV var) — i.e. it
    behaves as an alternate admin credential, not a scoped one. This is a
    known, documented limitation, not an oversight: inventing a
    bucket-per-DID or pin-per-DID ownership model wasn't asked for and
    would be its own design decision. `CACAO_OPERATOR_DIDS` defaults to
    empty, meaning **CACAO grants nothing at all** on these three surfaces
    until an operator DID is explicitly added.

All secrets are Worker secrets; operator copies are in the macOS Keychain,
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
