(ns kotobase-protocols-worker.core
  "Pure decision logic for the kotobase-protocols deploy shell —
  everything here is host-free so the nbb test suite covers it without
  a workerd runtime (same split as kotobase-cljc-worker: pure handler
  vs edge shell).

  The shell's storage model (ADR-2607174500): hydrate the WHOLE
  IStore state from one R2 object into kotobase.local/LocalStore, run
  the pure kotobase.protocols router synchronously, and persist the
  snapshot back with an etag-conditional put (optimistic lock, retry
  on conflict). Deliberately v0: single-object state bounds scale and
  write concurrency, in exchange for reusing LocalStore/snapshot as-is
  with zero async plumbing in the handlers."
  (:require [clojure.string :as str]
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

(defn authorized-write?
  "Writes need `authorization: Bearer <token>`. Fail closed: with no
  token configured every write is rejected (open reads stay fine) —
  an unauthenticated public S3/XRPC write surface must be impossible
  to deploy by accident."
  [req token]
  (boolean
   (and (string? token)
        (seq token)
        (= (get (:headers req) "authorization") (str "Bearer " token)))))

(defn unauthorized-response [token-configured?]
  {:status 401
   :headers {"content-type" "text/plain; charset=utf-8"
             "www-authenticate" "Bearer"}
   :body (if token-configured?
           "unauthorized: writes require a bearer token"
           "unauthorized: write token not configured (writes are disabled)")})

(defn state-changed?
  "Persist only when the handler actually mutated the store —
  LocalStore bumps :revision on every mutation."
  [before-snapshot after-snapshot]
  (not= (:revision before-snapshot) (:revision after-snapshot)))

(defn normalize-headers
  "Lower-case header names once at the boundary."
  [pairs]
  (into {} (map (fn [[k v]] [(str/lower-case k) v])) pairs))
