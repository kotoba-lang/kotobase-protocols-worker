(ns kotobase-protocols-worker.sigv4-test
  (:require [clojure.test :refer [deftest is testing]]
            [kotobase-protocols-worker.sigv4 :as sigv4]))

(def auth-header
  (str "AWS4-HMAC-SHA256 "
       "Credential=AKIDEXAMPLE/20260717/auto/s3/aws4_request, "
       "SignedHeaders=host;x-amz-content-sha256;x-amz-date, "
       "Signature=abc123def456"))

(deftest parse-authorization
  (let [p (sigv4/parse-authorization auth-header)]
    (is (= "AKIDEXAMPLE" (:akid p)))
    (is (= "20260717" (:date p)))
    (is (= "auto" (:region p)))
    (is (= "s3" (:service p)))
    (is (= ["host" "x-amz-content-sha256" "x-amz-date"] (:signed-headers p)))
    (is (= "abc123def456" (:signature p)))
    (is (= "20260717/auto/s3/aws4_request" (sigv4/scope p))))
  (testing "malformed → nil"
    (is (nil? (sigv4/parse-authorization nil)))
    (is (nil? (sigv4/parse-authorization "Bearer tok")))
    (is (nil? (sigv4/parse-authorization "AWS4-HMAC-SHA256 Credential=a/b/c, Signature=x")))))

(deftest canonical-query
  (is (= "" (sigv4/canonical-query nil)))
  (is (= "a=1&b=sp%20ace&z=~" (sigv4/canonical-query {"z" "~" "b" "sp ace" "a" "1"}))
      "sorted by key, RFC3986-encoded, tilde unreserved"))

(deftest canonical-request-shape
  (let [req {:method :put
             :path "/bkt/sig-test.txt"
             :query {}
             :headers {"host" "s3.kotobase.net"
                       "x-amz-content-sha256" "deadbeef"
                       "x-amz-date" "20260717T000000Z"}}
        cr (sigv4/canonical-request req ["host" "x-amz-content-sha256" "x-amz-date"]
                                    "deadbeef")]
    (is (= (str "PUT\n"
                "/bkt/sig-test.txt\n"
                "\n"
                "host:s3.kotobase.net\n"
                "x-amz-content-sha256:deadbeef\n"
                "x-amz-date:20260717T000000Z\n"
                "\n"
                "host;x-amz-content-sha256;x-amz-date\n"
                "deadbeef")
           cr)))
  (testing "string-to-sign framing"
    (is (= "AWS4-HMAC-SHA256\n20260717T000000Z\n20260717/auto/s3/aws4_request\ncafe"
           (sigv4/string-to-sign "20260717T000000Z" "20260717/auto/s3/aws4_request" "cafe")))))
