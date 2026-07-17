(ns kotobase-protocols-worker.worker
  "Cloudflare Worker shell for kotoba-lang/kotobase-protocols
  (ADR-2607174500, v0.2 ADR-2607176000, per-DID CACAO ADR-2607177000,
  real datom-plane backend ADR-2607177500). Owns transport + auth +
  persistence; all protocol logic lives in the pure library.

  Request flow:
    1. read raw body (ArrayBuffer) once; decode text view for the router
    2. writes: authorize — Bearer WRITE_TOKEN (full admin), AWS SigV4
       over the raw payload (S3_ACCESS_KEY_ID/S3_SECRET_ACCESS_KEY),
       or a CACAO (kotobase-protocols-worker.cacao): on the atproto
       surface a valid CACAO authorizes a write only when its issuer
       DID equals the request's `repo` field (per-DID, structural — no
       client-supplied target DID to disagree with, ADR-2607177000);
       on every other surface a valid CACAO is honored only when its
       issuer is in CACAO_OPERATOR_DIDS (admin-equivalent, same
       allowlist shape kotobase-cljc-worker's own `authorized?` uses)
    3. kotobase-protocols-worker.kotobase-store/hydrate-run-persist!
       does hydrate (real kotobase-peer content-addressed blocks in R2,
       not one opaque EDN blob) → LocalStore → pure router (sync) →
       diff → commit + head-CAS, all as ONE cycle (ADR-2607177500)
       – POST /ipfs short-circuits: sha256(raw body) → CIDv1 (library
         framing) → block stored base64 → {\"cid\": …}
    4. a lost head-CAS (:persisted false) retries the WHOLE cycle from
       a fresh head read, ≤3 attempts
    5. responses flagged :body-encoding :base64 (seeded git objects /
       ipfs blocks) are decoded back to raw bytes."
  (:require [clojure.string :as str]
            [kotobase-protocols-worker.cacao :as cacao]
            [kotobase-protocols-worker.core :as core]
            [kotobase-protocols-worker.kotobase-store :as ks]
            [kotobase-protocols-worker.sigv4 :as sigv4]
            [kotobase.protocols.blocks :as blocks]
            [kotobase.protocols.cid :as cid]
            [kotobase.protocols.json :as json]
            [kotobase.protocols.router :as router]))

;; Single shared graph — not yet per-tenant/per-DID (ADR-2607177500
;; not-decided: scoping this by the CACAO-authenticated DID, once one
;; is present, is the natural next step but out of THIS pass's scope,
;; same as the atproto per-DID auth work not inventing per-resource
;; ownership for the other three surfaces).
;;
;; v2, not v1: v1 accumulated ~150 unfolded commits across this
;; session's own testing (kotobase-store's commit-changes! didn't call
;; fold! yet) before that gap was found and fixed, degrading even a
;; plain read to >30s. Its blocks are harmless orphans in R2 (content-
;; addressed, no cleanup needed) but its HEAD is a known-bad starting
;; point to build on — v2 starts clean with folding wired in from
;; the first commit.
(def ^:private graph "kotobase-protocols-v2")

;; ---------------------------------------------------------------- bytes

(def ^:private text-encoder (js/TextEncoder.))
(def ^:private text-decoder (js/TextDecoder.))

(defn- te [s] (.encode text-encoder s))

(defn- ab->b64 [ab]
  (let [u8 (js/Uint8Array. ab)
        n (.-length u8)]
    (loop [i 0 s ""]
      (if (< i n)
        (recur (+ i 0x8000)
               (str s (.apply js/String.fromCharCode nil
                              (.subarray u8 i (min n (+ i 0x8000))))))
        (js/btoa s)))))

(defn- b64->u8 [b64]
  (let [bin (js/atob b64)]
    (js/Uint8Array.from bin (fn [c] (.charCodeAt c 0)))))

(defn- ab->hex [ab]
  (let [u8 (js/Uint8Array. ab)]
    (reduce (fn [s i] (str s (.padStart (.toString (aget u8 i) 16) 2 "0")))
            "" (range (.-length u8)))))

(defn- sha256 [data] (js/crypto.subtle.digest "SHA-256" data))

;; ---------------------------------------------------------------- sigv4

(defn- hmac [key-data data-str]
  (-> (js/crypto.subtle.importKey
       "raw" key-data #js {:name "HMAC" :hash "SHA-256"} false #js ["sign"])
      (.then (fn [k] (js/crypto.subtle.sign "HMAC" k (te data-str))))))

(defn- derive-signature [secret {:keys [date region service]} string-to-sign]
  (-> (hmac (te (str "AWS4" secret)) date)
      (.then #(hmac % region))
      (.then #(hmac % service))
      (.then #(hmac % "aws4_request"))
      (.then #(hmac % string-to-sign))
      (.then ab->hex)))

(defn- sigv4-verify
  "Promise<boolean>: recompute the request signature from the secrets
  and the RAW payload, require the declared payload hash to match."
  [^js env req body-ab]
  (let [p (sigv4/parse-authorization (get (:headers req) "authorization"))
        akid (.-S3_ACCESS_KEY_ID env)
        secret (.-S3_SECRET_ACCESS_KEY env)
        declared (get (:headers req) "x-amz-content-sha256")]
    (if-not (and p akid secret (= (:akid p) akid))
      (js/Promise.resolve false)
      (-> (.then (sha256 body-ab) ab->hex)
          (.then
           (fn [actual-hash]
             (let [payload-hash (or declared actual-hash)]
               (if (and declared
                        (not= declared "UNSIGNED-PAYLOAD")
                        (not= declared actual-hash))
                 false
                 (let [cr (sigv4/canonical-request req (:signed-headers p) payload-hash)]
                   (-> (.then (sha256 (te cr)) ab->hex)
                       (.then (fn [crh]
                                (derive-signature
                                 secret p
                                 (sigv4/string-to-sign
                                  (get (:headers req) "x-amz-date")
                                  (sigv4/scope p) crh))))
                       (.then (fn [sig] (= sig (:signature p))))))))))))))

(defn- atproto-surface?
  "Same host/path shape kotobase.protocols.router uses to route to the
  atproto handler — checked independently here (before the router
  runs) so the CACAO per-DID rule applies to exactly the requests that
  will land on that surface."
  [req]
  (or (= "atproto" (router/surface-of (:host req) "kotobase.net"))
      (str/starts-with? (or (:path req) "") "/xrpc/")))

(defn- cacao-authorized?
  "Promise<boolean>. Parses the body only on this fallback path (Bearer
  and SigV4 never need it) — a large S3/ipfs write body is never
  JSON-parsed just to look for a CACAO that isn't there."
  [^js env req]
  (let [parsed (try (json/parse (or (:body req) "{}")) (catch :default _ {}))
        token (cacao/from-request req parsed)
        issuer (some-> token cacao/verify-cacao)]
    (js/Promise.resolve
     (boolean
      (and issuer
           (if (atproto-surface? req)
             (= issuer (get parsed "repo"))
             (cacao/operator-allowed? issuer (.-CACAO_OPERATOR_DIDS env))))))))

(defn- write-authorized? [^js env req body-ab]
  (cond
    (core/authorized-write? req (.-WRITE_TOKEN env))
    (js/Promise.resolve true)

    (some-> (get (:headers req) "authorization")
            (str/starts-with? "AWS4-HMAC-SHA256 "))
    (sigv4-verify env req body-ab)

    :else (cacao-authorized? env req)))

;; ------------------------------------------------------------- requests

(defn- entries->map [entries]
  (into {} (map (fn [e] [(aget e 0) (aget e 1)])) (js/Array.from entries)))

(defn- req->ring [^js request body]
  (let [url (js/URL. (.-url request))]
    {:method (keyword (str/lower-case (.-method request)))
     :host (.-hostname url)
     :path (.-pathname url)
     :query (entries->map (.entries (.-searchParams url)))
     :headers (core/normalize-headers (entries->map (.entries (.-headers request))))
     :body (when (seq body) body)}))

(defn- ring->response [{:keys [status headers body body-encoding]}]
  (js/Response. (cond
                  (nil? body) js/undefined
                  (= :base64 body-encoding) (b64->u8 body)
                  :else body)
                (clj->js {:status status :headers (or headers {})})))

;; ---------------------------------------------------------- persistence

(defn- ipfs-post-response [store {:keys [cid b64 content-type]}]
  (blocks/put-block! store cid {:bytes b64 :encoding "base64"
                                :content-type content-type})
  {:status 201
   :headers {"content-type" "application/json"
             "location" (str "/ipfs/" cid)}
   :body (json/encode {"cid" cid})})

(defn- run-once
  "extra may carry :ipfs-post {:cid :b64 :content-type} — a shell-level
  write that bypasses the (read-only) ipfs HTTP surface. One full
  hydrate→run→diff→commit cycle against the real chain — reads
  naturally no-op (their after-state never differs from the hydrated
  seed) via kotobase-store's own :docs/:streams diff, no separate
  write?/state-changed? gate needed here anymore."
  [^js env req extra]
  (ks/hydrate-run-persist!
   (.-STATE_BUCKET env) (or (.-KOTOBASE_R2_PREFIX env) "") graph
   (fn [seed]
     (let [{:keys [store state]} (core/make-store seed)
           ctx {:store store
                :apex (or (.-APEX env) "kotobase.net")
                :now (.toISOString (js/Date.))}
           resp (if-let [ip (:ipfs-post extra)]
                  (ipfs-post-response store ip)
                  (router/handle ctx req))]
       {:after-state @state :response resp}))))

(defn- with-retries [^js env req extra]
  (letfn [(attempt [n]
            (.then (run-once env req extra)
                   (fn [{:keys [response persisted]}]
                     (cond
                       persisted (ring->response response)
                       (pos? n) (attempt (dec n))
                       :else (ring->response
                              {:status 503
                               :headers {"content-type" "text/plain; charset=utf-8"
                                         "retry-after" "1"}
                               :body "state write conflict, retry"})))))]
    (attempt 2)))

(defn- ipfs-post? [req]
  (and (= :post (:method req))
       (or (= "/ipfs" (:path req))
           (and (= "/" (:path req))
                (= "ipfs" (router/surface-of (:host req) "kotobase.net"))))))

(defn- handle-request [^js env req body-ab]
  (-> (if (core/write? req)
        (write-authorized? env req body-ab)
        (js/Promise.resolve true))
      (.then
       (fn [ok?]
         (cond
           (not ok?)
           (ring->response
            (core/unauthorized-response (some? (.-WRITE_TOKEN env))))

           (ipfs-post? req)
           (-> (sha256 body-ab)
               (.then (fn [digest]
                        (with-retries
                          env req
                          {:ipfs-post
                           {:cid (cid/cidv1-raw-sha256
                                  (vec (js/Array.from (js/Uint8Array. digest))))
                            :b64 (ab->b64 body-ab)
                            :content-type (or (get (:headers req) "content-type")
                                              "application/octet-stream")}}))))

           :else (with-retries env req nil))))))

(def handler
  #js {:fetch (fn [^js request ^js env _ctx]
                (-> (.arrayBuffer request)
                    (.then (fn [ab]
                             (let [body (.decode text-decoder ab)]
                               (handle-request env (req->ring request body) ab))))
                    (.catch (fn [e]
                              (js/Response. (str "internal error: " (.-message e))
                                            #js {:status 500})))))})
