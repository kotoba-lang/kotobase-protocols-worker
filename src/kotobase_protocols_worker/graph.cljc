(ns kotobase-protocols-worker.graph
  "Which R2 head/chain a request targets (ADR-2607178000) — pure
  decision logic, host-free, same split as core.cljc (nbb-testable,
  no npm crypto needed).

  The 4 atproto repo.*Record NSIDs resolve to a per-repo-DID graph
  (`atproto-repo/<did>`, derived from the `repo` query param on reads
  or body field on writes) — no auth needed to know WHERE to read,
  same principle as kotobase-cljc-worker's own
  canonical-graph(issuer, db_name) derivation. Combined with the
  write-side CACAO check (issuer must equal `repo` — see
  kotobase-protocols-worker.cacao/kotobase-protocols-worker.worker),
  a write only ever reaches a per-DID graph when the verified signer
  IS that DID: the same structural guarantee, just built from two
  already-separately-tested pieces instead of one derivation function.

  Every other request — s3/git/pinning, and atproto's OWN
  sync.getBlob (reads the SHARED block space POST /ipfs populates,
  not any repo's own doc space) — uses the single shared admin graph."
  (:require [kotoba.lang.text :as str]
            [kotobase.protocols.json :as json]
            [kotobase.protocols.router :as router]))

;; v2, not v1: v1 accumulated ~150 unfolded commits across a session's
;; own testing (kotobase-store's commit-changes! didn't call fold! yet)
;; before that gap was found and fixed, degrading even a plain read to
;; >30s (ADR-2607177500). Its blocks are harmless orphans in R2
;; (content-addressed, no cleanup needed) but its HEAD is a known-bad
;; starting point to build on — v2 starts clean with folding wired in
;; from the first commit.
(def shared-graph "kotobase-protocols-v2")

(def atproto-record-nsids
  #{"com.atproto.repo.getRecord" "com.atproto.repo.putRecord"
    "com.atproto.repo.deleteRecord" "com.atproto.repo.listRecords"})

(defn atproto-surface?
  "Same host/path shape kotobase.protocols.router uses to route to the
  atproto handler — checked independently here so the per-DID rules
  (this ns and kotobase-protocols-worker.cacao) apply to exactly the
  requests that will land on that surface."
  [req]
  (or (= "atproto" (router/surface-of (:host req) "kotobase.net"))
      (str/starts-with? (or (:path req) "") "/xrpc/")))

(defn- repo-of [req]
  (or (get (:query req) "repo")
      (get (try (json/parse (or (:body req) "{}")) (catch #?(:clj Exception :cljs :default) _ {}))
           "repo")))

(defn for-request
  "Cheap for every non-atproto request (two checks, no parsing); only a
  matching atproto repo.*Record request parses its body/query for
  `repo` — never a large S3/ipfs binary body."
  [req]
  (or (when (and (atproto-surface? req)
                 (some atproto-record-nsids (str/split (or (:path req) "") #"/")))
        (when-let [repo (repo-of req)]
          (str "atproto-repo/" repo)))
      shared-graph))
