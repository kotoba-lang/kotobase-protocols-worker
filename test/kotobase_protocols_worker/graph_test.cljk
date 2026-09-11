(ns kotobase-protocols-worker.graph-test
  (:require [clojure.test :refer [deftest is testing]]
            [kotobase-protocols-worker.graph :as graph]))

(def did "did:key:z6MkExample00000000000000000000000000000000")

(deftest atproto-record-ops-get-a-per-did-graph
  (testing "GET getRecord/listRecords — repo from query param"
    (is (= (str "atproto-repo/" did)
           (graph/for-request {:host "atproto.kotobase.net" :method :get
                               :path "/xrpc/com.atproto.repo.getRecord"
                               :query {"repo" did}})))
    (is (= (str "atproto-repo/" did)
           (graph/for-request {:host "atproto.kotobase.net" :method :get
                               :path "/xrpc/com.atproto.repo.listRecords"
                               :query {"repo" did}}))))
  (testing "POST putRecord/deleteRecord — repo from JSON body"
    (is (= (str "atproto-repo/" did)
           (graph/for-request {:host "atproto.kotobase.net" :method :post
                               :path "/xrpc/com.atproto.repo.putRecord"
                               :body (str "{\"repo\":\"" did "\",\"collection\":\"c\",\"rkey\":\"r\"}")})))
    (is (= (str "atproto-repo/" did)
           (graph/for-request {:host "atproto.kotobase.net" :method :post
                               :path "/xrpc/com.atproto.repo.deleteRecord"
                               :body (str "{\"repo\":\"" did "\"}")}))))
  (testing "single-origin /xrpc/ fallback path (no atproto host) resolves the same way"
    (is (= (str "atproto-repo/" did)
           (graph/for-request {:host "peer.local" :method :get
                               :path "/xrpc/com.atproto.repo.getRecord"
                               :query {"repo" did}})))))

(deftest non-record-atproto-uses-shared-graph
  (testing "sync.getBlob reads the shared block space, not a repo's doc space"
    (is (= graph/shared-graph
           (graph/for-request {:host "atproto.kotobase.net" :method :get
                               :path "/xrpc/com.atproto.sync.getBlob"
                               :query {"did" did "cid" "bafkrei..."}}))))
  (testing "unknown/unimplemented nsid falls back to shared too"
    (is (= graph/shared-graph
           (graph/for-request {:host "atproto.kotobase.net" :method :get
                               :path "/xrpc/app.bsky.feed.getTimeline"})))))

(deftest other-surfaces-always-shared
  (is (= graph/shared-graph
         (graph/for-request {:host "s3.kotobase.net" :method :put :path "/bkt/k" :body "v"})))
  (is (= graph/shared-graph
         (graph/for-request {:host "git.kotobase.net" :method :get :path "/o/r/info/refs"})))
  (is (= graph/shared-graph
         (graph/for-request {:host "pinning.kotobase.net" :method :post :path "/pins"
                             :body (str "{\"cid\":\"bafkrei...\"}")}))))

(deftest missing-repo-falls-back-to-shared-not-a-crash
  (is (= graph/shared-graph
         (graph/for-request {:host "atproto.kotobase.net" :method :get
                             :path "/xrpc/com.atproto.repo.getRecord"
                             :query {}})))
  (is (= graph/shared-graph
         (graph/for-request {:host "atproto.kotobase.net" :method :post
                             :path "/xrpc/com.atproto.repo.putRecord"
                             :body "not json"}))))

(deftest two-different-dids-get-different-graphs
  (let [other-did "did:key:z6MkOther1111111111111111111111111111111"
        g1 (graph/for-request {:host "atproto.kotobase.net" :method :get
                               :path "/xrpc/com.atproto.repo.getRecord"
                               :query {"repo" did}})
        g2 (graph/for-request {:host "atproto.kotobase.net" :method :get
                               :path "/xrpc/com.atproto.repo.getRecord"
                               :query {"repo" other-did}})]
    (is (not= g1 g2))
    (is (not= g1 graph/shared-graph))
    (is (not= g2 graph/shared-graph))))
