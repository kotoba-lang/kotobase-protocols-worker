(ns kotobase-protocols-worker.cacao-test
  "Real crypto — mints a genuine CACAO via kotobase-client and verifies it
  through this Worker's own copy of the check (ADR-2607177000). shadow-cljs
  :node-test, not nbb: kotobase-client's own test suite uses the same
  target because verify needs real @noble/curves/@ipld/dag-cbor npm
  modules, and cljs ranks above nbb in the repo-wide runtime priority."
  (:require [cljs.test :refer-macros [deftest is testing]]
            ["@noble/curves/ed25519.js" :refer [ed25519]]
            [kotobase.cacao :as client-cacao]
            [kotobase.cid :as cid]
            [kotobase-protocols-worker.cacao :as cacao]))

(def seed (js/Uint8Array.from (clj->js (range 32))))
(def did (cid/did-key-from-ed25519-pub (.getPublicKey ed25519 seed)))
(def other-seed (js/Uint8Array.from (clj->js (range 1 33))))
(def other-did (cid/did-key-from-ed25519-pub (.getPublicKey ed25519 other-seed)))

(defn- mint
  ([] (mint {}))
  ([overrides]
   (:cacao-b64
    (client-cacao/mint-cacao
     (merge {:secret-key seed :aud "did:web:kotobase.net"
             :capability "kotobase:pin" :graph did
             :now-ms 0 :nonce "testnonce0000000"}
            overrides)))))

(deftest verify-cacao-round-trip
  (testing "valid, unexpired CACAO → issuer DID"
    (is (= did (cacao/verify-cacao (mint {:now-ms (js/Date.now)})))))
  (testing "expired CACAO (fixed now-ms 0, no ttl override) → nil"
    (is (nil? (cacao/verify-cacao (mint)))))
  (testing "garbage input → nil, never throws"
    (is (nil? (cacao/verify-cacao "not-a-cacao")))
    (is (nil? (cacao/verify-cacao "")))))

(deftest verify-cacao-signature-must-match-claimed-issuer
  ;; a CACAO whose :iss doesn't match the key that actually signed it
  ;; must never verify — this is the forgery case per-DID auth depends on.
  (let [forged (client-cacao/mint-cacao
                {:secret-key other-seed :aud "did:web:kotobase.net"
                 :capability "kotobase:pin" :graph did
                 :now-ms (js/Date.now) :nonce "testnonce0000000"})]
    (is (not= did (:did forged)) "sanity: different keys produce different DIDs")
    (is (= other-did (cacao/verify-cacao (:cacao-b64 forged)))
        "verify returns the ACTUAL signer, not any claimed identity")))

(deftest from-request-body-field-takes-precedence
  (is (= "b64-from-body"
         (cacao/from-request {:headers {"authorization" "CACAO b64-from-header"}}
                             {"cacao_b64" "b64-from-body"})))
  (is (= "b64-from-header"
         (cacao/from-request {:headers {"authorization" "CACAO b64-from-header"}} {})))
  (is (nil? (cacao/from-request {:headers {"authorization" "Bearer tok"}} {})))
  (is (nil? (cacao/from-request {:headers {}} {}))))

(deftest operator-allowed?
  (is (cacao/operator-allowed? "did:key:zA" "did:key:zA,did:key:zB"))
  (is (cacao/operator-allowed? "did:key:zB" " did:key:zA , did:key:zB "))
  (is (not (cacao/operator-allowed? "did:key:zC" "did:key:zA,did:key:zB")))
  (testing "no allowlist configured → CACAO grants nothing, not everything"
    (is (not (cacao/operator-allowed? "did:key:zA" nil)))
    (is (not (cacao/operator-allowed? "did:key:zA" "")))
    (is (not (cacao/operator-allowed? "did:key:zA" "   ")))
    (is (not (cacao/operator-allowed? nil "did:key:zA")))))
