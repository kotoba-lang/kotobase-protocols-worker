# kotobase-protocols-worker

[![CI](https://github.com/kotoba-lang/kotobase-protocols-worker/actions/workflows/ci.yml/badge.svg)](https://github.com/kotoba-lang/kotobase-protocols-worker/actions/workflows/ci.yml)

Cloudflare Worker **deploy shell** for
[kotoba-lang/kotobase-protocols](https://github.com/kotoba-lang/kotobase-protocols)
(ADR-2607174500 in `com-junkawasaki/root`). Serves, live:

| Host | Surface |
|---|---|
| `s3.kotobase.net` | S3 object API |
| `atproto.kotobase.net` | AT-Proto XRPC tenant data-plane |
| `pinning.kotobase.net` | [IPFS Pinning Service API](https://ipfs.github.io/pinning-services-api-spec/) |
| `kotobase-protocols-worker.*.workers.dev` | all of the above **plus git**, via `/s3/*`, `/xrpc/*`, `/git/*`, `/ipfs/*`, `/pins*` |

`ipfs.kotobase.net` is deliberately **not** routed here — that hostname is
owned by `gftdcojp/net-kotobase-ipfs` (ADR-2607072000). `git.kotobase.net`
is ALSO not routed here, but for a different, non-deliberate reason: a
concurrent session's own Worker (Cloudflare service `kotobase-git`) claimed
that custom domain out from under this one mid-session (custom domains are
single-owner; the last `wrangler deploy` to declare a route wins, with no
conflict surfaced to either side) — see ADR-2607177500's incident log.
Re-claiming it would mean fighting a concurrent session for a shared
resource, so the git surface is fully real and fully tested, just currently
reachable only via `/git/*` on workers.dev, not a `git.` subdomain.

## How it persists

A real content-addressed **kotobase-peer** datom-plane chain in R2
(ADR-2607177500) — NOT an opaque blob. `kotobase-protocols-worker.kotobase-store`
bridges the pure, synchronous `kotobase.protocols.*` handlers (which call
`IStore` as plain values, never Promises — a public-library contract this
repo does not touch) to the engine's Promise-returning, content-addressed
persistence:

1. `hydrate!` walks the graph's current `hot-datoms` into a plain
   `{:docs :streams}` map (a `kotobase.local/LocalStore` seed)
2. the Worker's existing `make-store`→`router/handle` sequence runs
   synchronously against that seed, exactly as before
3. `commit-changes!` diffs before/after, commits ONLY the touched docs/
   events as datom quads, and folds novelty once it crosses the engine's
   default threshold (64 tx-blocks) — **do not skip this**: an earlier
   version of this bridge didn't fold, and a session's worth of testing
   (~150 unfolded commits) degraded a plain list read to >30s before the
   gap was found and fixed. `should-fold?`/`fold!` are called on every
   write now.
4. the new chain-cid is CAS'd into the graph's R2 head pointer
   (`onlyIf: {etagMatches}`, ported from `kotobase-cljc-worker`'s own
   `r2-put-head-if-match` including its documented first-write-to-a-new-
   graph race window); a lost CAS retries the WHOLE cycle from a fresh
   head, ≤3 attempts, then `503`.

One shared graph (`kotobase-protocols-v2`) for now — not yet per-tenant/
per-DID; scoping storage by the CACAO-authenticated DID (below) is the
natural next step, out of this pass's scope.

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
into the git surface so it clones over dumb-HTTP. Currently workers.dev
only (see the git.kotobase.net note above):

```bash
KOTOBASE_WRITE_TOKEN=$TOKEN nbb bin/seed_git.cljs \
  <local-repo> kotoba-lang/<name> https://kotobase-protocols-worker.<account>.workers.dev/git
git clone https://kotobase-protocols-worker.<account>.workers.dev/git/kotoba-lang/<name>
```

Verified end to end (2026-07-17): seeding this repo's own 85 objects and
cloning the result back produced a working tree **byte-identical** to the
source (`diff -rq`, zero output) against the real content-addressed
backend above.

## Develop

```bash
# pure-logic tests (core/sigv4; nbb, first-class runtime)
nbb --classpath "src:test:../kotobase-protocols/src:../kotobase/src" bin/run_tests.cljs

# real-crypto tests (CACAO verify + the datom-store bridge; needs real
# @noble/curves/@ipld/dag-cbor/@noble/hashes — shadow-cljs :node-test,
# not nbb, same reason kotobase-client's own suite avoids nbb)
npm ci
npx shadow-cljs compile test && node out/node-tests.js

# build (in the superproject, go through the resource governor)
npx shadow-cljs release worker     # → out/worker.js (:esm)

# deploy
npx wrangler deploy
printf '%s' "$TOKEN" | npx wrangler secret put WRITE_TOKEN
```

Library deps are shadow `:source-paths` to sibling west checkouts —
`../kotobase-protocols`, `../kotobase`, `../kotobase-client` (CACAO), and
the real engine's dep chain `../kotobase-peer`, `../datom`, `../arrangement`,
`../prolly-tree`, `../chain`, `../io-ipld`, `../io-multiformats`,
`../org-ietf-cbor` — the same pattern `kotobase-cljc-worker` uses, and in
fact `kotobase_r2.cljs`/`kotobase_crypto.cljc` are direct ports of that
repo's own `r2.cljs`/`crypto.cljc` (R2 block-store trampoline, head-CAS,
the documented plaintext-passthrough crypto profile from ADR-2607051000).

## License

Apache-2.0
