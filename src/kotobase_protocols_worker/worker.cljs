(ns kotobase-protocols-worker.worker
  "Cloudflare Worker shell for kotoba-lang/kotobase-protocols
  (ADR-2607174500). Owns transport + auth + persistence; all protocol
  logic lives in the pure library.

  Request flow:
    1. hydrate: GET <STATE_BUCKET>/kotobase-protocols/state.edn →
       LocalStore seed (+ etag)
    2. run kotobase.protocols.router/handle synchronously
    3. writes only: persist LocalStore snapshot back, etag-conditional
       (onlyIf etagMatches) — on conflict rehydrate and re-run, up to
       3 attempts, then 503.

  Bindings (wrangler.jsonc): STATE_BUCKET (R2), APEX var,
  WRITE_TOKEN secret (absent ⇒ writes fail closed, 401)."
  (:require [cljs.reader :as reader]
            [clojure.string :as str]
            [kotobase-protocols-worker.core :as core]
            [kotobase.protocols.router :as router]))

(def state-key "kotobase-protocols/state.edn")

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

(defn- ring->response [{:keys [status headers body]}]
  (js/Response. (or body js/undefined)
                (clj->js {:status status :headers (or headers {})})))

(defn- hydrate [^js env]
  (-> (.get (.-STATE_BUCKET env) state-key)
      (.then (fn [^js obj]
               (if obj
                 (.then (.text obj)
                        (fn [txt] {:seed (reader/read-string txt)
                                   :etag (.-etag obj)}))
                 {:seed nil :etag nil})))))

(defn- persist [^js env snapshot etag]
  ;; nil etag = first-ever write: unconditional create. With an etag,
  ;; onlyIf etagMatches makes R2 return null on a lost race.
  (let [opts (when etag #js {:onlyIf #js {:etagMatches etag}})]
    (-> (.put (.-STATE_BUCKET env) state-key (pr-str snapshot) opts)
        (.then (fn [put-result] (some? put-result))))))

(defn- run-once [^js env req]
  (-> (hydrate env)
      (.then (fn [{:keys [seed etag]}]
               (let [{:keys [store state]} (core/make-store seed)
                     before @state
                     ctx {:store store
                          :apex (or (.-APEX env) "kotobase.net")
                          :now (.toISOString (js/Date.))}
                     resp (router/handle ctx req)
                     after @state]
                 (if (and (core/write? req) (core/state-changed? before after))
                   (.then (persist env after etag)
                          (fn [ok?] {:resp resp :persisted ok?}))
                   {:resp resp :persisted true}))))))

(defn- handle-request [^js env req]
  (if (and (core/write? req)
           (not (core/authorized-write? req (.-WRITE_TOKEN env))))
    (js/Promise.resolve
     (ring->response (core/unauthorized-response (some? (.-WRITE_TOKEN env)))))
    (letfn [(attempt [n]
              (.then (run-once env req)
                     (fn [{:keys [resp persisted]}]
                       (cond
                         persisted (ring->response resp)
                         (pos? n) (attempt (dec n))
                         :else (ring->response
                                {:status 503
                                 :headers {"content-type" "text/plain; charset=utf-8"
                                           "retry-after" "1"}
                                 :body "state write conflict, retry"})))))]
      (attempt 2))))

(def handler
  #js {:fetch (fn [^js request ^js env _ctx]
                (-> (.text request)
                    (.then (fn [body] (handle-request env (req->ring request body))))
                    (.catch (fn [e]
                              (js/Response. (str "internal error: " (.-message e))
                                            #js {:status 500})))))})
