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

(deftest break-glass-is-distinguishable-from-a-customer-s-own-authority
  ;; The three write paths used to collapse to `true`, so a write made with the
  ;; operator's Bearer token looked in the record exactly like one a customer's
  ;; DID authorised. That is the question an audit is actually asked — `was the
  ;; emergency credential used?` — and a boolean cannot answer it.
  (let [bearer (core/write-authority {:kind :break-glass})
        cacao (core/write-authority {:kind :cacao :subject "did:key:zAlice"})
        sigv4 (core/write-authority {:kind :sigv4 :subject "AKIAEXAMPLE"})
        none (core/write-authority {:kind :none})]
    (testing "each admits, and says which one it was"
      (is (core/admitted? bearer))
      (is (core/admitted? cacao))
      (is (core/admitted? sigv4))
      (is (not (core/admitted? none))))

    (testing "and they are not the same value"
      (is (= 3 (count (distinct (map :authority/kind [bearer cacao sigv4]))))))

    (testing "the break-glass credential is named for what it is"
      ;; it is not removed: an operator locked out of a tenant needs a way in,
      ;; and a system without one gets a worse one improvised. It must not be
      ;; invisible.
      (is (= :break-glass (:authority/kind bearer)))
      (is (= :operator (:authority/subject bearer))))

    (testing "its reach is a written value, not an inference from silence"
      ;; unchanged reach — this is not a narrowing — but an audit that has to
      ;; deduce `covers everything` from the absence of a scope cannot report it
      (is (= :all (:authority/surfaces bearer)))
      (is (= :all core/break-glass-surfaces)))

    (testing "a CACAO write records whose DID authorised it"
      (is (= "did:key:zAlice" (:authority/subject cacao))))

    (testing "an unadmitted write carries no subject and no reach"
      (is (nil? (:authority/subject none)))
      (is (= #{} (:authority/surfaces none))))))

(deftest an-unknown-authority-kind-admits-nothing
  ;; fail closed: a kind this model does not know is not treated as the nearest
  ;; one it does
  (is (not (core/admitted? (core/write-authority {:kind :something-new}))))
  (is (not (core/admitted? (core/write-authority {})))))

(deftest the-predicate-still-answers-for-callers-that-only-need-it
  ;; `authorized-write?` is kept so this change does not break callers that
  ;; only ask yes/no; new code takes the authority so what admitted the write
  ;; survives into the record
  (let [req (fn [h] {:method :put :headers {"authorization" h}})]
    (is (core/authorized-write? (req "Bearer t0k3n") "t0k3n"))
    (is (core/break-glass? (req "Bearer t0k3n") "t0k3n"))
    (is (not (core/authorized-write? (req "Bearer wrong") "t0k3n")))
    ;; fail closed with nothing configured, unchanged
    (is (not (core/break-glass? (req "Bearer anything") nil)))))
