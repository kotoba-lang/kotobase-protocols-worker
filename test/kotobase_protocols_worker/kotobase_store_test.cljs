(ns kotobase-protocols-worker.kotobase-store-test
  "KotobaseStore ≡ LocalStore: every scenario here runs through BOTH the
  real content-addressed engine (via an in-memory fake R2 bucket — same
  shape a real Cloudflare binding exposes: .get/.put with
  onlyIf.etagMatches) and a plain kotobase.local/LocalStore, and asserts
  their :docs/:streams end up identical after each step AND survive a
  fresh hydrate (a true round-trip through the chain, not just an
  in-memory check). shadow-cljs :node-test — the engine's crypto seam
  needs real @noble/hashes/@ipld/dag-cbor, same reason cacao-test avoids
  nbb (ADR-2607177500)."
  (:require [cljs.test :refer-macros [deftest testing async]]
            [cljs.test :as t]
            [kotobase-peer.core :as eng]
            [kotobase.local :as local]
            [kotobase.store :as st]
            [kotobase-protocols-worker.kotobase-r2 :as r2]
            [kotobase-protocols-worker.kotobase-store :as ks]))

;; ---------------------------------------------------------- fake R2
;; Minimal in-memory stand-in for the Cloudflare R2 binding: .get/.put
;; Promise-returning, honoring opts.onlyIf.etagMatches for the head-CAS
;; path exactly as the real binding does.

(defn fake-bucket []
  (let [store (atom {}) ;; key -> {:val string|Uint8Array :etag int}
        next-etag (atom 0)]
    #js {:get (fn [k]
                (js/Promise.resolve
                 (when-let [{:keys [val etag]} (get @store k)]
                   #js {:text (fn [] (js/Promise.resolve val))
                        :arrayBuffer (fn [] (js/Promise.resolve (.-buffer val)))
                        :etag (str etag)})))
         :put (fn [k v opts]
                (js/Promise.resolve
                 (let [current (get @store k)
                       required (some-> opts .-onlyIf .-etagMatches)]
                   (if (and required (not= required (some-> current :etag str)))
                     nil
                     (do (swap! store assoc k {:val v :etag (swap! next-etag inc)})
                         true)))))}))

;; -------------------------------------------------------------- ops

(defn- apply-op! [store [op & args]]
  (case op
    :put (apply st/-put store args)
    :append (apply st/-append store args)))

(def ops-1
  [[:put [:s3 "bkt"] "a.txt" {:body "hello"}]
   [:put [:s3 "bkt"] "b.txt" {:body "world"}]
   [:append :audit {:op :create :k "a.txt"}]
   [:append :audit {:op :create :k "b.txt"}]
   [:put [:s3 "bkt"] "a.txt" nil]                 ; delete/tombstone
   [:put [:atproto "did:x" "coll"] "r1" {:v 1}]])

(defn- content [snap] (select-keys snap [:docs :streams]))

(defn- run-through-datom-store!
  "Applies `ops` one at a time, each through its OWN
  hydrate-run-persist! cycle (so every step is a genuine chain commit,
  not one big in-memory batch), and resolves with the FINAL hydrated
  content (a fresh hydrate! of the resulting head, proving persistence
  round-trips, not just that the in-memory diff was correct)."
  [bucket ops]
  (letfn [(step [remaining]
            (if (empty? remaining)
              (js/Promise.resolve nil)
              (-> (ks/hydrate-run-persist!
                   bucket "" "test-graph"
                   (fn [seed]
                     (let [store (local/local-store seed)]
                       (apply-op! store (first remaining))
                       {:after-state (content (local/snapshot store))
                        :response nil})))
                  (.then (fn [{:keys [persisted]}]
                           (when-not persisted
                             (throw (ex-info "CAS lost in a single-writer test — should never happen" {})))
                           (step (rest remaining)))))))]
    (-> (step ops)
        (.then (fn [_]
                 (ks/hydrate-run-persist!
                  bucket "" "test-graph"
                  (fn [seed] {:after-state (content seed) :response (content seed)})))))))

(deftest datom-store-equals-local-store
  (async done
   (let [oracle (local/local-store)]
     (doseq [op ops-1] (apply-op! oracle op))
     (let [expected (content (local/snapshot oracle))]
       (-> (run-through-datom-store! (fake-bucket) ops-1)
           (.then
            (fn [{:keys [response]}]
              (testing "content-addressed round-trip (multiple sequential commits + a fresh hydrate) matches the LocalStore oracle exactly"
                (t/is (= (:docs expected) (:docs response)))
                (t/is (= (:streams expected) (:streams response))))
              (done)))
           (.catch (fn [e]
                     (t/is false (str "unexpected rejection: " (.-message e) "\n" (.-stack e)))
                     (done))))))))

(deftest empty-graph-hydrates-empty
  (async done
   (-> (ks/hydrate-run-persist!
        (fake-bucket) "" "brand-new-graph"
        (fn [seed] {:after-state (content seed) :response seed}))
       (.then (fn [{:keys [response persisted]}]
                (t/is persisted)
                (t/is (= {} (:docs response)))
                (t/is (= {} (:streams response)))
                (done)))
       (.catch (fn [e] (t/is false (.-message e)) (done))))))

(deftest concurrent-writers-one-wins-one-retries
  ;; r2-put-head-if-match's FIRST write to a brand-new graph is an
  ;; unconditional put (no prior etag to CAS against, ported verbatim
  ;; from kotobase-cljc-worker's own documented, accepted limitation —
  ;; see kotobase-r2.cljs) — so seed the graph with one real commit
  ;; first, establishing a genuine etag, THEN race two writers against
  ;; that. Only from a real etag does the CAS actually protect anything.
  (async done
   (let [bucket (fake-bucket)]
     (-> (ks/hydrate-run-persist!
          bucket "" "race-graph"
          (fn [seed]
            (let [store (local/local-store seed)]
              (st/-put store [:s3 "bkt"] "seed" {:v :seed})
              {:after-state (content (local/snapshot store)) :response nil})))
         (.then
          (fn [_]
            (js/Promise.all
             #js [(ks/hydrate-run-persist!
                   bucket "" "race-graph"
                   (fn [seed]
                     (let [store (local/local-store seed)]
                       (st/-put store [:s3 "bkt"] "writer-a" {:v :a})
                       {:after-state (content (local/snapshot store)) :response :a})))
                  (ks/hydrate-run-persist!
                   bucket "" "race-graph"
                   (fn [seed]
                     (let [store (local/local-store seed)]
                       (st/-put store [:s3 "bkt"] "writer-b" {:v :b})
                       {:after-state (content (local/snapshot store)) :response :b})))])))
         (.then (fn [results]
                  (let [[a b] (vec results)]
                    (t/is (not= (:persisted a) (:persisted b))
                          "exactly one of the two racing writers must lose the CAS"))
                  (done)))
         (.catch (fn [e] (t/is false (.-message e)) (done)))))))

(deftest novelty-folds-past-the-threshold
  ;; ADR-2607177500 incident: without commit-changes! folding, novelty
  ;; grows unboundedly and even a plain read degrades badly (found live:
  ;; ~150 unfolded commits made a list read take >30s in production).
  ;; Push MORE than default-fold-threshold (64) individual commits
  ;; through hydrate-run-persist! and assert novelty-size comes back
  ;; DOWN, not up — proving fold! actually ran, not just that content
  ;; still happens to be correct (which the equivalence test above
  ;; already covers, at a scale too small to ever trigger folding).
  (async done
   (let [bucket (fake-bucket)]
     (letfn [(write-one [i]
               (ks/hydrate-run-persist!
                bucket "" "fold-graph"
                (fn [seed]
                  (let [store (local/local-store seed)]
                    (st/-put store [:s3 "bkt"] (str "k" i) {:i i})
                    {:after-state (content (local/snapshot store)) :response nil}))))
             (write-n [n]
               (if (zero? n)
                 (js/Promise.resolve nil)
                 (.then (write-one n) (fn [_] (write-n (dec n))))))]
       (-> (write-n 70) ;; > default-fold-threshold (64)
           (.then
            (fn [_]
              (r2/with-blocks
               (fn [cid] (r2/cached-block-bytes bucket "" cid))
               (fn [get-fn]
                 (-> (r2/r2-get-head bucket (r2/head-key "" "fold-graph"))
                     (.then (fn [{:keys [chain]}] (eng/novelty-size get-fn chain))))))))
           (.then (fn [n]
                    (t/is (< n 70)
                          (str "novelty-size after 70 commits should have been folded down, got " n))
                    (t/is (< n 64)
                          "should-fold?'s own threshold means it must be below 64 post-fold")
                    (done)))
           (.catch (fn [e] (t/is false (str (.-message e) "\n" (.-stack e))) (done))))))))

(deftest diagnose-empty-graph
  (async done
   (-> (ks/diagnose! (fake-bucket) "" "never-touched-graph")
       (.then (fn [{:keys [chain-present? novelty-size should-fold?]}]
                (t/is (false? chain-present?))
                (t/is (= 0 novelty-size))
                (t/is (false? should-fold?))
                (done)))
       (.catch (fn [e] (t/is false (.-message e)) (done))))))

(deftest diagnose-after-one-commit-is-read-only
  (async done
   (let [bucket (fake-bucket)]
     (-> (ks/hydrate-run-persist!
          bucket "" "diag-graph"
          (fn [seed]
            (let [store (local/local-store seed)]
              (st/-put store [:s3 "bkt"] "k" {:v 1})
              {:after-state (content (local/snapshot store)) :response nil})))
         (.then (fn [_] (ks/diagnose! bucket "" "diag-graph")))
         (.then (fn [d1]
                  (t/is (true? (:chain-present? d1)))
                  (t/is (= 1 (:novelty-size d1)) "one commit, no fold yet, no prior novelty")
                  (t/is (false? (:should-fold? d1)) "1 < default threshold 64")
                  (ks/diagnose! bucket "" "diag-graph")))
         (.then (fn [d2]
                  (t/is (= 1 (:novelty-size d2))
                        "calling diagnose! must not itself mutate novelty (read-only)")
                  (done)))
         (.catch (fn [e] (t/is false (str (.-message e) "\n" (.-stack e))) (done)))))))
