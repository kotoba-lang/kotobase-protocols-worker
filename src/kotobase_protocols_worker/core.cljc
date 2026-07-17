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

(defn normalize-headers
  "Lower-case header names once at the boundary."
  [pairs]
  (into {} (map (fn [[k v]] [(str/lower-case k) v])) pairs))
