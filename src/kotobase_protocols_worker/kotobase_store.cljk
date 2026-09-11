(ns kotobase-protocols-worker.kotobase-store
  "IStore↔datom encoding: represents kotobase.local/LocalStore's exact
  state shape — `{:docs {coll {k v}} :streams {stream [event...]} :seq n
  :revision n}` — as datom quads on the real kotobase-peer content-
  addressed engine, so the Worker's persisted backend becomes real
  prolly-tree blocks + a verifiable commit chain in R2 instead of one
  opaque EDN blob (ADR-2607177500).

  This module does NOT implement kotobase.store/IStore directly — the
  engine's persistence calls (`commit!`/`hot-datoms`) are Promise-
  returning on cljs (the crypto seam, ADR-2607051000), but every
  kotobase.protocols.* handler calls IStore synchronously. Retrofitting
  that would mean changing a public library's documented 'pure sync
  handler' contract. Instead: `hydrate!` (async) rebuilds a plain
  LocalStore-shaped map from the chain BEFORE the synchronous router
  runs (exactly where the Worker's existing R2-blob hydrate already
  sat), and `commit-changes!` (async) diffs before/after LocalStore
  state and commits ONLY the touched docs/streams AFTER the handler
  returns. Zero changes to kotobase-protocols or the handler call shape.

  Entity model (one graph, unscoped by tenant — see the ADR's
  not-decided section):
    doc   entity id = (pr-str [:doc coll k]), attrs \"doc/coll\"
          (pr-str coll), \"doc/key\" (pr-str k), \"doc/val\" (pr-str v).
          \"doc/val\" is the only attr ever retracted+reasserted (LocalStore
          keeps a tombstoned key in :docs with a nil value rather than
          removing it — see s3.cljc's own -list/keep dance — so a
          delete here also keeps the entity, just re-asserts
          (pr-str nil), matching that exactly).
    event entity id = (pr-str [:event stream seq]), attrs
          \"doc/stream\" (pr-str stream), \"doc/event\" (pr-str event-map,
          :seq embedded in the map itself so hydrate! can sort by it —
          no separate \"doc/seq\" attr, nothing reads one back). Streams
          are append-only — an event entity, once asserted, is never
          retracted. `seq` itself is just `(count already-hydrated
          events for that stream)` at diff time — no separate counter
          entity: a lost head-CAS means the next attempt re-hydrates
          (and therefore re-counts) from the fresh head before
          recomputing, so retries never collide on seq the way a
          counter cached across attempts could."
  (:require [clojure.edn :as edn]
            [ipld.core :as ipld]
            [kotobase-peer.core :as eng]
            [kotobase-protocols-worker.kotobase-crypto :as crypto]
            [kotobase-protocols-worker.kotobase-r2 :as r2]))

(def visible-all (constantly true))

;; ------------------------------------------------------------- encoding

(defn- doc-eid [coll k] (pr-str [:doc coll k]))
(defn- event-eid [stream seq] (pr-str [:event stream seq]))
(defn- counter-eid [stream] (pr-str [:seq-counter stream]))

(defn- rows->doc-val
  "rows for one doc eid → its current \"doc/val\" edn-string, or nil."
  [rows]
  (some #(when (= "doc/val" (:a %)) (:v_edn %)) rows))

(defn- decode2
  "hot-datoms' :v_edn is (pr-str stored-o); every attr here stores
  stored-o as (pr-str original-value) (see the ns docstring's entity
  model), so recovering `original-value` needs edn/read-string TWICE —
  once for hot-datoms' own wrapping, once for ours. (diff->tx-data!'s
  retraction path needs only the FIRST layer — the exact raw stored
  string — to build a matching [:db/retract] quad, so it stays a
  single edn/read-string; only decode-for-callers goes through here.)"
  [v_edn]
  (edn/read-string (edn/read-string v_edn)))

;; ---------------------------------------------------------------- read

(defn hydrate!
  "chain-cid → Promise<LocalStore-shaped state map>, or an EMPTY state
  for a nil chain-cid (first-ever write to this graph). Walks every
  \"doc/coll\"+\"doc/key\"+\"doc/val\" and \"doc/stream\"+\"doc/seq\"+
  \"doc/event\" row via one hot-datoms scan (index :aevt, so every
  attribute's rows come back grouped) and folds them back into
  {:docs {...} :streams {...} :seq n :revision n}. `:revision`/`:seq`
  are recovered as event/doc counts (not persisted separately — the
  chain itself is the revision log).

  `async-get-fn` (REQUIRED, same guardrail rationale as `fold-if-due!`'s):
  this is a FULL-PREFIX scan — no `:components`, so prolly-tree's prefix
  pruning cannot bound it and the walk touches every block of the :aevt
  index. Over the `with-blocks` sync trampoline that costs O(N) SEQUENTIAL
  R2 round trips (one block discovered per retry) and O(N²) node decodes
  (each retry re-walks and re-decodes from the root, since the trampoline
  caches bytes, not decoded nodes). `kotobase-peer.core/hot-datoms`'s
  7-arity routes the snapshot half through `cold-datoms-async` /
  `prolly-tree.core/scan-prefix-async` — concurrent per level, each node
  decoded once — which is the same fix `fold-if-due!` already applies to
  the fold's own hydrate. This call site was left on the sync path when
  kotoba-lang/kotobase-protocols-worker#1 fixed the fold path, so the READ
  path kept paying the cost the WRITE path had stopped paying.

  Measured (kotobase-peer bench/results/2026-08-01-dag-shape.edn): the
  :aevt tree is WIDE and SHALLOW — height 2-3, fanout ~10 — so the sync
  trampoline's round trips scale with block COUNT while the async walk's
  scale with tree HEIGHT. The unfolded-novelty half is a cons chain and
  stays sequential under both."
  [get-fn chain-cid async-get-fn]
  (-> (eng/hot-datoms get-fn chain-cid {:index :aevt} visible-all
                      crypto/blind-fn crypto/decrypt-fn async-get-fn)
      (.then
       (fn [rows]
         (let [by-e (group-by :e rows)
               doc-eids (into #{} (comp (filter #(= "doc/coll" (:a %))) (map :e)) rows)
               event-eids (into #{} (comp (filter #(= "doc/stream" (:a %))) (map :e)) rows)
               docs (reduce
                     (fn [acc eid]
                       (let [attrs (by-e eid)
                             coll (decode2 (some #(when (= "doc/coll" (:a %)) (:v_edn %)) attrs))
                             k (decode2 (some #(when (= "doc/key" (:a %)) (:v_edn %)) attrs))
                             v (decode2 (rows->doc-val attrs))]
                         (assoc-in acc [coll k] v)))
                     {} doc-eids)
               events (reduce
                       (fn [acc eid]
                         (let [attrs (by-e eid)
                               stream (decode2 (some #(when (= "doc/stream" (:a %)) (:v_edn %)) attrs))
                               event (decode2 (some #(when (= "doc/event" (:a %)) (:v_edn %)) attrs))]
                           (update acc stream (fnil conj []) event)))
                       {} event-eids)
               events (reduce-kv (fn [m s evs] (assoc m s (vec (sort-by :seq evs)))) {} events)]
           {:docs docs
            :streams events
            :seq (reduce + 0 (map count (vals events)))
            :revision (+ (count doc-eids) (count event-eids))})))))

;; --------------------------------------------------------------- write

(defn- doc-point-query
  "Promise<vec of rows> for one known eid — a cheap :eavt point lookup,
  used to find the OLD \"doc/val\" quad (if any) to retract before
  asserting the new one (this substrate has no cardinality-one; an
  unretracted re-assert would leave both values visible).

  `async-get-fn` for the same reason as `hydrate!`'s, with a smaller
  blast radius: `:components [eid]` DOES let prolly-tree prune to one
  root-to-leaf path, so this walk touches O(tree height) blocks rather
  than all of them — but under the sync trampoline even those are
  discovered one per retry, and this runs once per changed doc in a
  write, so the round trips multiply by the diff size."
  [get-fn chain-cid eid async-get-fn]
  (eng/hot-datoms get-fn chain-cid {:index :eavt :components [eid]} visible-all
                  crypto/blind-fn crypto/decrypt-fn async-get-fn))

(defn diff->tx-data!
  "Promise<tx-data vec> for the docs/streams that actually changed
  between `before` and `after` (both LocalStore-shaped state maps —
  the Worker computes this from its existing before/after :docs/:streams
  snapshots, so only genuinely touched entities enter tx-data, keeping
  every commit O(diff) like kotobase-peer's own commit! promises, not
  O(whole graph)). `async-get-fn` — see `doc-point-query`."
  [get-fn chain-cid before after async-get-fn]
  (let [changed-docs
        (for [[coll kvs] (:docs after)
              [k v] kvs
              :when (not= v (get-in before [:docs coll k] ::absent))]
          [coll k v])
        new-events
        (for [[stream evs] (:streams after)
              :let [before-n (count (get-in before [:streams stream]))]
              ev (drop before-n evs)]
          [stream ev])]
    (-> (js/Promise.all
         (clj->js (for [[coll k _v] changed-docs]
                    (doc-point-query get-fn chain-cid (doc-eid coll k) async-get-fn))))
        (.then
         (fn [rows-per-doc]
           (let [doc-tx
                 (mapcat
                  (fn [[coll k v] rows]
                    (let [eid (doc-eid coll k)
                          old-val-edn (rows->doc-val rows)
                          coll-known? (some #(= "doc/coll" (:a %)) rows)]
                      (cond-> []
                        old-val-edn (conj [:db/retract eid "doc/val" (edn/read-string old-val-edn)])
                        true (conj [:db/add eid "doc/val" (pr-str v)])
                        (not coll-known?) (conj [:db/add eid "doc/coll" (pr-str coll)])
                        (not coll-known?) (conj [:db/add eid "doc/key" (pr-str k)]))))
                  changed-docs (vec rows-per-doc))
                event-tx
                (mapcat
                 (fn [[stream ev] i]
                   (let [seq (+ (count (get-in before [:streams stream])) i 1)
                         eid (event-eid stream seq)]
                     ;; \"doc/seq\" isn't asserted as its own attr — the
                     ;; seq is embedded in the event map itself
                     ;; (\"doc/event\", via assoc below) and hydrate!
                     ;; sorts events by that, so a separate attr would
                     ;; be redundant, never read back.
                     [[:db/add eid "doc/stream" (pr-str stream)]
                      [:db/add eid "doc/event" (pr-str (assoc ev :seq seq))]]))
                 new-events (range))]
             (vec (concat doc-tx event-tx))))))))

(defn- fold-if-due!
  "After a commit, fold novelty into the indexed snapshot once it crosses
  the engine's default threshold (64 tx-blocks) — WITHOUT this, every
  hot-datoms read walks an ever-growing novelty chain and both reads and
  writes degrade without bound (found live, 2026-07-17: a shared graph
  that accumulated ~150+ unfolded commits across a session's worth of
  testing made even a plain read take >30s). `should-fold?`/`novelty-
  size` are pure state-field reads (O(1), no decrypt needed) so this
  check itself is cheap on every commit.

  `async-get-fn` (REQUIRED, not optional — see the ns-level guardrail note
  below) is threaded to `eng/fold!`'s async-scan arity: fold's own
  pre-fold hydrate walks the ENTIRE indexed snapshot via
  `prolly-tree.core/scan-prefix`, and over the `with-blocks` sync-retry
  trampoline (`kotobase-protocols-worker.kotobase-r2`) that walk is O(N²)
  in the number of distinct blocks touched — confirmed live elsewhere in
  this org (gftdcojp/app-aozora#78 / ADR-2607120730): a 5130-leaf
  snapshot exceeded a 300s CPU budget over the sync path vs 806ms via
  `scan-prefix-async`. `kotobase-cljc-worker.handler/do-fold` (the
  reference implementation this module is a deploy shell for) already
  wires this same `async-get-fn` into its own `eng/fold!` call — this
  fn was missing it (kotoba-lang/kotobase-protocols-worker#1)."
  [put! get-fn chain-cid async-get-fn]
  (if (eng/should-fold? get-fn chain-cid)
    (eng/fold! put! get-fn chain-cid ipld/link? nil
               crypto/blind-fn crypto/encrypt-fn crypto/decrypt-fn
               nil nil async-get-fn)
    (js/Promise.resolve chain-cid)))

(defn commit-changes!
  "Promise<new-chain-cid | prev-chain-cid> — commits the before/after
  diff (empty diff → resolves to prev-chain-cid unchanged, no-op write),
  folding afterward if the engine's own threshold says novelty is due.
  `async-get-fn` — see `fold-if-due!`."
  [put! get-fn chain-cid before after async-get-fn]
  (-> (diff->tx-data! get-fn chain-cid before after async-get-fn)
      (.then (fn [tx-data]
               (if (empty? tx-data)
                 (js/Promise.resolve chain-cid)
                 (-> (eng/commit! put! get-fn tx-data chain-cid crypto/encrypt-fn)
                     (.then #(fold-if-due! put! get-fn % async-get-fn))))))))

;; --------------------------------------------------------------- diag

(defn diagnose!
  "Read-only health signal for `graph` (ADR-2607178500): no hydrate, no
  LocalStore, no write — just the engine's own O(1) `novelty-size`/
  `should-fold?` state-field reads via the SAME R2 trampoline every
  other call in this module uses. Exists because diagnosing the
  unfolded-novelty incident (ADR-2607177500) required manually timing
  a plain read and guessing at the cause — this makes that observable
  directly, without live forensics.
  → Promise<{:chain-present? bool :novelty-size int :should-fold? bool}>."
  [^js bucket pfx graph]
  (-> (r2/r2-get-head bucket (r2/head-key pfx graph))
      (.then
       (fn [{:keys [chain]}]
         (if (nil? chain)
           (js/Promise.resolve {:chain-present? false :novelty-size 0 :should-fold? false})
           (r2/with-blocks
            (fn [cid] (r2/cached-block-bytes bucket pfx cid))
            (fn [get-fn]
              {:chain-present? true
               :novelty-size (eng/novelty-size get-fn chain)
               :should-fold? (eng/should-fold? get-fn chain)})))))))

;; --------------------------------------------------------- R2 wiring

(defn hydrate-run-persist!
  "The Worker's whole per-request cycle against the real content-
  addressed chain: read the graph's head, hydrate a LocalStore-shaped
  seed from it, hand that seed to `run-fn` (the Worker's existing
  make-store→router/handle→snapshot sequence — this module knows
  nothing about kotobase.protocols.router), diff the result against
  the seed, and — only when :docs/:streams actually changed — commit
  the diff and CAS the head.

  `run-fn` is `(fn [seed]) -> {:after-state map :response resp}`.
  Ported get-fn/put! buffering is INCIDENT 2607032800's fix
  (kotobase-cljc-worker's run-write-attempt docstring): commit!'s own
  novelty-size re-reads the chain-cid it just committed BEFORE this fn
  flushes to R2, so get-fn must check the in-memory buffer first.
  `async-get-fn` (threaded to `commit-changes!`/`fold-if-due!`, see
  their docstrings) gets the SAME buffer-first check — NOT a direct,
  unbuffered R2 fetch like `kotobase-cljc-worker.worker/run-write-
  attempt`'s own `:async-get-fn`: if THIS request's own `commit!` is
  what crosses the fold threshold, its just-buffered (not yet flushed
  to R2) tx-block is exactly the kind of cid `fold!`'s novelty-read
  step needs back, and an unbuffered async fetch would either return
  nil (nothing at that key in R2 yet) into `ipld/decode`, which throws,
  or — the more insidious failure — a stale/absent read gets silently
  treated as \"nothing there\", losing that tx-block from the fold's
  merged state. This may be a latent bug in the reference
  implementation's own analogous `:async-get-fn`
  (kotoba-lang/kotobase-cljc-worker, flagged separately, not fixed
  here) — this module closes it for its own copy by construction.

  → Promise<{:response resp :persisted bool}>; :persisted false means
  another writer's head update landed first — the Worker's own retry
  loop (unchanged from today) re-runs the whole cycle from a fresh head."
  [^js bucket pfx graph run-fn]
  (let [buffer (atom {})
        async-get-fn (fn [cid]
                       (if (contains? @buffer cid)
                         (js/Promise.resolve (get @buffer cid))
                         (r2/cached-block-bytes bucket pfx cid)))]
    (-> (r2/r2-get-head bucket (r2/head-key pfx graph))
        (.then
         (fn [{:keys [chain etag]}]
           (r2/with-blocks
            (fn [cid] (r2/cached-block-bytes bucket pfx cid))
            (fn [sync-get]
              (let [get-fn (fn [cid] (if (contains? @buffer cid) (get @buffer cid) (sync-get cid)))
                    put! (fn [cid bytes] (swap! buffer assoc cid bytes))]
                (-> (hydrate! get-fn chain async-get-fn)
                    (.then
                     (fn [before]
                       (let [{:keys [after-state response]} (run-fn before)]
                         (if (and (= (:docs before) (:docs after-state))
                                  (= (:streams before) (:streams after-state)))
                           (js/Promise.resolve {:response response :persisted true})
                           (-> (commit-changes! put! get-fn chain before after-state async-get-fn)
                               (.then
                                (fn [new-chain]
                                  (-> (js/Promise.all
                                       (clj->js (map (fn [[cid bytes]]
                                                       (r2/r2-put-bytes bucket (r2/block-key pfx cid) bytes))
                                                     @buffer)))
                                      (.then (fn [_]
                                               (r2/r2-put-head-if-match
                                                bucket (r2/head-key pfx graph) new-chain etag)))
                                      (.then (fn [cas-ok?]
                                               {:response response :persisted cas-ok?})))))))))))))))))))
