(ns kotobase-protocols-worker.sigv4
  "AWS Signature V4 verification — the PURE half (ADR-2607176000).

  Everything here is deterministic string work (credential parsing,
  canonical request, string-to-sign), so nbb tests cover it directly;
  the HMAC-SHA256 chain needs WebCrypto and lives in the worker shell.
  Scope: header-based auth for the s3 surface as `curl --aws-sigv4` /
  aws-sdk emit it. Presigned query auth and chunked payloads are out of
  scope v0."
  (:require [clojure.string :as str]))

(defn parse-authorization
  "\"AWS4-HMAC-SHA256 Credential=AKID/date/region/service/aws4_request,
  SignedHeaders=a;b, Signature=hex\" → map, or nil when malformed."
  [auth]
  (when (and (string? auth) (str/starts-with? auth "AWS4-HMAC-SHA256 "))
    (let [kvs (into {}
                    (keep (fn [part]
                            (let [[k v] (str/split (str/trim part) #"=" 2)]
                              (when (and k v) [k v]))))
                    (str/split (subs auth (count "AWS4-HMAC-SHA256 ")) #","))
          cred (some-> (get kvs "Credential") (str/split #"/"))]
      (when (and (= 5 (count (or cred []))) (get kvs "SignedHeaders") (get kvs "Signature"))
        (let [[akid date region service terminal] cred]
          (when (= "aws4_request" terminal)
            {:akid akid :date date :region region :service service
             :signed-headers (str/split (get kvs "SignedHeaders") #";")
             :signature (get kvs "Signature")}))))))

(defn scope [{:keys [date region service]}]
  (str date "/" region "/" service "/aws4_request"))

(defn- uri-encode-char [c]
  (let [code #?(:clj (int (.charAt ^String c 0)) :cljs (.charCodeAt c 0))
        hexs #?(:clj (str/upper-case (format "%02x" code))
                :cljs (.padStart (str/upper-case (.toString code 16)) 2 "0"))]
    (str "%" hexs)))

(defn uri-encode
  "RFC 3986 percent-encode (unreserved chars pass through). ASCII-only
  v0 — the shell never re-encodes paths (URL.pathname arrives encoded),
  this is for query canonicalization."
  [s]
  (str/replace (str s) #"[^A-Za-z0-9\-._~]" uri-encode-char))

(defn canonical-query
  "Query map → canonical query string (sorted by encoded key, then value)."
  [query]
  (->> query
       (map (fn [[k v]] [(uri-encode k) (uri-encode v)]))
       (sort-by (fn [[k v]] [k v]))
       (map (fn [[k v]] (str k "=" v)))
       (str/join "&")))

(defn canonical-headers [headers signed-headers]
  (apply str (for [h signed-headers]
               (str h ":" (str/trim (str (get headers h))) "\n"))))

(defn canonical-request
  "req is the shell's ring map (lower-cased headers). payload-hash is
  the hex sha256 of the raw body (or UNSIGNED-PAYLOAD)."
  [req signed-headers payload-hash]
  (str (str/upper-case (name (:method req))) "\n"
       (or (:path req) "/") "\n"
       (canonical-query (:query req)) "\n"
       (canonical-headers (:headers req) signed-headers) "\n"
       (str/join ";" signed-headers) "\n"
       payload-hash))

(defn string-to-sign [amz-date credential-scope canonical-request-sha256-hex]
  (str "AWS4-HMAC-SHA256\n" amz-date "\n" credential-scope "\n"
       canonical-request-sha256-hex))
