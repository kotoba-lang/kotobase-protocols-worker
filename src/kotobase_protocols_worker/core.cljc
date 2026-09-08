(ns kotobase-protocols-worker.core
  "Pure decision logic for the kotobase-protocols deploy shell —
  everything here is host-free so the nbb test suite covers it without
  a workerd runtime (same split as kotobase-cljc-worker: pure handler
  vs edge shell).

  `make-store` seeds a plain in-process kotobase.local/LocalStore that
  the pure kotobase.protocols router runs against synchronously for
  ONE request — same LocalStore either standalone (OSS) or, wired to
  the real content-addressed backend, as the per-request in-memory
  materialization kotobase-protocols-worker.kotobase-store hydrates
  from and diffs back to R2 (ADR-2607177500)."
  (:require [kotoba.lang.text :as str]
            [kotobase.local :as local]))

(def empty-state
  {:docs {} :streams {} :seq 0 :revision 0 :tx-receipts {}})

(defn make-store
  "LocalStore over an atom the shell owns, so state snapshots are plain
  `@state` — no deftype field access (kotobase.local/snapshot reads
  `.-state`, which compiled cljs supports but nbb/SCI does not; owning
  the atom sidesteps the difference)."
  [seed]
  (let [state (atom (merge empty-state seed))]
    {:store (local/->LocalStore state) :state state}))

(def write-methods #{:put :post :delete})

(defn write? [req] (contains? write-methods (:method req)))

(def break-glass-surfaces
  "What the Bearer admin token covers.

  `:all` is written down rather than inferred from the absence of a scope. It
  is the same reach it always had — this is not a narrowing — but an audit that
  has to deduce `this credential covers everything` from silence cannot report
  it, and a deployment that wants to narrow it needs somewhere to say so."
  :all)

(defn break-glass?
  "Whether this request presents the Bearer admin token.

  Fail closed: with no token configured every write is rejected (open reads
  stay fine) — an unauthenticated public S3/XRPC write surface must be
  impossible to deploy by accident."
  [req token]
  (boolean
   (and (string? token)
        (seq token)
        (= (get (:headers req) "authorization") (str "Bearer " token)))))

(defn write-authority
  "Which authority admits this write, as a value.

  The three paths — the Bearer admin token, AWS SigV4, and a per-DID CACAO —
  used to collapse to `true`, so a write made with the break-glass credential
  was indistinguishable in the record from one a customer's own DID authorised.
  That is the question an audit is actually asked, and a boolean cannot answer
  it.

  `:break-glass` is named for what it is. It is not removed: an operator
  locked out of a tenant needs a way in, and a system without one gets a worse
  one improvised. What it must not be is invisible."
  [{:keys [kind subject surfaces]}]
  (case kind
    :break-glass {:authority/kind :break-glass
                  :authority/surfaces (or surfaces break-glass-surfaces)
                  :authority/subject :operator}
    :sigv4 {:authority/kind :sigv4
            :authority/surfaces (or surfaces break-glass-surfaces)
            :authority/subject (or subject :unknown-access-key)}
    :cacao {:authority/kind :cacao
            :authority/surfaces (or surfaces #{:atproto})
            :authority/subject subject}
    {:authority/kind :none :authority/surfaces #{} :authority/subject nil}))

(defn admitted?
  "Whether an authority admits the write at all. A separate question from which
  authority it was, and both belong in the record."
  [authority]
  (not= :none (:authority/kind authority)))

(defn authorized-write?
  "Kept for callers that only need the predicate. New code should take the
  authority instead, so what admitted the write survives into the record."
  [req token]
  (break-glass? req token))

(defn unauthorized-response [token-configured?]
  {:status 401
   :headers {"content-type" "text/plain; charset=utf-8"
             "www-authenticate" "Bearer"}
   :body (if token-configured?
           "unauthorized: writes require a bearer token"
           "unauthorized: write token not configured (writes are disabled)")})

(defn normalize-headers
  "Lower-case header names once at the boundary."
  [pairs]
  (into {} (map (fn [[k v]] [(str/lower k) v])) pairs))
