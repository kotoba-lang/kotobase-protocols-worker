(ns kotobase-protocols-worker.core-test
  (:require [clojure.test :refer [deftest is testing]]
            #?(:cljs [cljs.reader])
            [kotobase-protocols-worker.core :as core]
            [kotobase.protocols.router :as router]))

(deftest write-detection
  (is (core/write? {:method :put}))
  (is (core/write? {:method :post}))
  (is (core/write? {:method :delete}))
  (is (not (core/write? {:method :get})))
  (is (not (core/write? {:method :head}))))

(deftest write-authorization
  (let [req #(hash-map :method :put :headers {"authorization" %})]
    (is (core/authorized-write? (req "Bearer t0k3n") "t0k3n"))
    (is (not (core/authorized-write? (req "Bearer wrong") "t0k3n")))
    (is (not (core/authorized-write? {:method :put :headers {}} "t0k3n")))
    (testing "fail closed when no token configured"
      (is (not (core/authorized-write? (req "Bearer anything") nil)))
      (is (not (core/authorized-write? (req "Bearer ") "")))
      (is (= 401 (:status (core/unauthorized-response false)))))))

(deftest state-change-detection-via-revision
  (let [{:keys [store state]} (core/make-store nil)
        ctx {:store store :apex "kotobase.net"}
        before @state]
    (router/handle ctx {:method :get :host "s3.kotobase.net" :path "/bkt"})
    (is (not (core/state-changed? before @state))
        "reads do not require persistence")
    (router/handle ctx {:method :put :host "s3.kotobase.net"
                        :path "/bkt/k" :body "v"})
    (is (core/state-changed? before @state))))

(deftest snapshot-seed-round-trip
  ;; the shell's whole persistence model: state → pr-str → read →
  ;; seed a fresh store → same responses
  (let [{:keys [store state]} (core/make-store nil)
        ctx {:store store :apex "kotobase.net"}]
    (router/handle ctx {:method :put :host "s3.kotobase.net"
                        :path "/bkt/k" :body "hello"})
    (let [snap @state
          store2 (:store (core/make-store
                          #?(:clj  (read-string (pr-str snap))
                             :cljs (cljs.reader/read-string (pr-str snap)))))
          resp (router/handle {:store store2 :apex "kotobase.net"}
                              {:method :get :host "s3.kotobase.net" :path "/bkt/k"})]
      (is (= 200 (:status resp)))
      (is (= "hello" (:body resp))))))

(deftest header-normalization
  (is (= {"content-type" "a" "authorization" "b"}
         (core/normalize-headers [["Content-Type" "a"] ["AUTHORIZATION" "b"]]))))
