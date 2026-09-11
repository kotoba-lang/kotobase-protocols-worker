(ns kotobase-protocols-worker.worker-test
  "The SigV4 write-auth path, driven end to end.

  Canonicalization and the HMAC ladder moved to kotoba-lang/sigv4, which proves
  them against AWS's published vectors. What that cannot prove is that *this*
  worker still composes them correctly — the akid check, the payload-hash
  check, and the header set it feeds the verifier. So these tests sign a
  request with the shared library, exactly as an S3 client would, and require
  the worker to accept it — then require it to reject each way it should."
  (:require [cljs.test :refer [deftest is testing async]]
            [kotobase-protocols-worker.worker :as worker]
            [sigv4.core :as v4]
            [sigv4.crypto :as crypto]
            [sigv4.protocols :as p]))

(def akid "AKIDEXAMPLE")
(def secret "wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY")
(def env #js {:S3_ACCESS_KEY_ID akid :S3_SECRET_ACCESS_KEY secret})

(def c (crypto/crypto))
(def amz-date "20260725T120000Z")
(def short-date "20260725")
(def region "auto")

(defn- body-bytes [s] (.-buffer (.encode (js/TextEncoder.) s)))

(defn- sign-request
  "Build a request signed the way an S3 client signs it. → Promise<req>."
  [{:keys [body path]}]
  (let [payload-hash-p (p/-sha256-hex c body)]
    (.then payload-hash-p
           (fn [payload-hash]
             (let [headers {"host" "s3.kotobase.net"
                            "x-amz-content-sha256" payload-hash
                            "x-amz-date" amz-date}
                   {:keys [canonical-request signed-headers]}
                   (v4/canonical-request {:method :put :path path :query ""
                                          :headers headers
                                          :payload-hash payload-hash})
                   scope (v4/credential-scope short-date region)
                   {:keys [seed steps]} (v4/signing-key-chain secret short-date region)]
               (-> (p/-sha256-hex c canonical-request)
                   (.then (fn [cr-hash]
                            (let [sts (v4/string-to-sign amz-date scope cr-hash)]
                              (-> (reduce (fn [pr step] (.then pr #(p/-hmac c % step)))
                                          (js/Promise.resolve seed) steps)
                                  (.then #(p/-hmac c % sts))
                                  (.then #(p/-hex c %))))))
                   (.then (fn [signature]
                            {:method :put :path path :query {} :body body
                             :headers (assoc headers "authorization"
                                             (v4/authorization-header
                                              akid scope signed-headers signature))}))))))))

(deftest a-correctly-signed-write-is-accepted
  (async done
    (let [body (body-bytes "hello kotobase")]
      (-> (sign-request {:body "hello kotobase" :path "/bkt/a.txt"})
          (.then #(worker/sigv4-verify env % body))
          (.then (fn [ok?] (is (true? ok?) "a request signed by a real S3 client must verify") (done)))
          (.catch (fn [e] (is false (str e)) (done)))))))

(deftest a-non-ascii-key-is-accepted
  (testing "the copy this replaced encoded with charCodeAt, so a non-ASCII key
            signed as UTF-16 and could never have verified"
    (async done
      (let [body (body-bytes "x")]
        (-> (sign-request {:body "x" :path (v4/object-path "bkt" "日本語 file.txt")})
            (.then #(worker/sigv4-verify env % body))
            (.then (fn [ok?] (is (true? ok?)) (done)))
            (.catch (fn [e] (is false (str e)) (done))))))))

(deftest a-tampered-body-is-rejected
  (async done
    (-> (sign-request {:body "hello kotobase" :path "/bkt/a.txt"})
        (.then #(worker/sigv4-verify env % (body-bytes "hello attacker")))
        (.then (fn [ok?] (is (false? ok?) "the declared payload hash must match the body received") (done)))
        (.catch (fn [e] (is false (str e)) (done))))))

(deftest a-tampered-path-is-rejected
  (async done
    (let [body (body-bytes "hello kotobase")]
      (-> (sign-request {:body "hello kotobase" :path "/bkt/a.txt"})
          (.then #(worker/sigv4-verify env (assoc % :path "/bkt/elsewhere.txt") body))
          (.then (fn [ok?] (is (false? ok?)) (done)))
          (.catch (fn [e] (is false (str e)) (done)))))))

(deftest an-unknown-access-key-is-rejected
  (async done
    (let [body (body-bytes "x")]
      (-> (sign-request {:body "x" :path "/bkt/a.txt"})
          (.then #(worker/sigv4-verify #js {:S3_ACCESS_KEY_ID "OTHER"
                                            :S3_SECRET_ACCESS_KEY secret}
                                       % body))
          (.then (fn [ok?] (is (false? ok?)) (done)))
          (.catch (fn [e] (is false (str e)) (done)))))))

(deftest a-wrong-secret-is-rejected
  (async done
    (let [body (body-bytes "x")]
      (-> (sign-request {:body "x" :path "/bkt/a.txt"})
          (.then #(worker/sigv4-verify #js {:S3_ACCESS_KEY_ID akid
                                            :S3_SECRET_ACCESS_KEY "not-the-secret"}
                                       % body))
          (.then (fn [ok?] (is (false? ok?)) (done)))
          (.catch (fn [e] (is false (str e)) (done)))))))
