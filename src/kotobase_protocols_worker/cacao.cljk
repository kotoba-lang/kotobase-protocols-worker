(ns kotobase-protocols-worker.cacao
  "CACAO write-credential verification (ADR-2607177000): a byte-exact port
  of kotobase-cljc-worker's own edge verify path (worker.cljs `verify-cacao`),
  reusing kotobase-client's mint-side SIWE/did:key code so the check is
  identical to what kotobase.net itself does — not a reimplementation of
  the crypto, just this Worker's copy of the same verify call.

  `verify-cacao` returns the ISSUER DID string on a valid, unexpired,
  well-formed CACAO, or nil otherwise. It does not by itself authorize
  anything — same split as kotobase-cljc-worker (`authorized?` is a
  separate, caller-supplied decision). See ADR-2607177000 for how this
  Worker uses the returned DID: on the atproto surface, a write is
  authorized only when the CACAO's issuer equals the request's `repo`
  field (per-DID enforcement, structural — same principle as
  kotobase-cljc-worker's `canonical-graph(issuer, db_name)` derivation,
  simplified to a direct equality since this Worker's atproto records
  are already explicitly repo-scoped). Other surfaces (s3/git/pinning)
  have no DID-shaped resource identity yet, so a valid CACAO there is
  honored only when its issuer is in the CACAO_OPERATOR_DIDS allowlist —
  the exact allowlist pattern kotobase-cljc-worker's own `authorized?`
  uses for its non-per-resource writes (fold). See the repo README for
  why per-resource DID scoping on those three surfaces is deliberately
  NOT invented here."
  (:require [clojure.string :as str]
            [kotobase.cacao :as cacao]
            [kotobase.cid :as cid]
            ["@ipld/dag-cbor" :as dag-cbor]
            ["@noble/curves/ed25519.js" :refer [ed25519]]))

(defn- expired? [exp]
  (or (nil? exp)
      (let [t (.getTime (js/Date. exp))]
        (or (js/Number.isNaN t) (< t (js/Date.now))))))

(defn verify-cacao
  "base64(DAG-CBOR) CACAO string → issuer did:key string, or nil.
  Verbatim port of kotobase-cljc-worker's worker.cljs `verify-cacao`."
  [cacao-b64]
  (try
    (let [^js env (.decode dag-cbor (cacao/base64->bytes cacao-b64))
          ^js p (.-p env)
          iss (.-iss p)
          pub (cid/did-key->ed25519-pub iss)
          exp (.-exp p)
          p-clj {:domain (.-domain p) :iss iss :aud (.-aud p) :version (.-version p)
                 :nonce (.-nonce p) :iat (.-iat p) :exp exp :statement (.-statement p)
                 :resources (vec (.-resources p))}
          msg (cacao/cacao-siwe-message p-clj)
          sig (cacao/base64url->bytes (.. env -s -s))]
      (when (and pub (not (expired? exp)) (.verify ed25519 sig (cid/text->bytes msg) pub))
        iss))
    (catch :default _ nil)))

(defn from-request
  "Pull the CACAO out of a ring req: JSON body field `cacao_b64` (matches
  kotobase-cljc-worker's own client contract) or an
  `authorization: CACAO <b64>` header, body field taking precedence."
  [{:keys [headers] :as req} parsed-body]
  (or (get parsed-body "cacao_b64")
      (some-> (get headers "authorization")
              (as-> a (when (str/starts-with? a "CACAO ") (subs a 6))))))

(defn operator-allowed?
  "issuer ∈ allowlist. allowlist is a CSV string (possibly nil/blank = no
  CACAO-as-admin at all — fail closed, mirrors kotobase-cljc-worker's own
  KOTOBASE_OPERATOR_DIDS empty-string-means-open convention being
  explicitly opted OUT of here: an absent allowlist means CACAO grants
  NOTHING on non-atproto surfaces, not everything."
  [issuer allowlist-csv]
  (boolean
   (and issuer (string? allowlist-csv) (seq (str/trim allowlist-csv))
        (contains? (set (map str/trim (str/split allowlist-csv #","))) issuer))))
