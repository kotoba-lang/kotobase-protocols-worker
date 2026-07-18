;; Guardrail against re-introducing kotoba-lang/kotobase-protocols-worker#1
;; (kotobase-peer.core/fold! called without :async-get-fn, paying the O(N^2)
;; with-blocks sync-retry trampoline cost on every fold — the same pattern
;; ADR-2607120730/gftdcojp/app-aozora#78 already diagnosed and
;; kotobase-cljc-worker's do-fold already avoids). Run:
;;   nbb bin/lint_engine_calls.cljs
(ns lint-engine-calls
  (:require ["fs" :as fs]
            [cljs.reader :as reader]
            [clojure.string :as str]))

(def target-files
  ["src/kotobase_protocols_worker/kotobase_store.cljs"])

(def min-fold-args
  "put! get-fn chain-cid ref? max-novelty blind-fn encrypt-fn decrypt-fn
  cache-get cache-put! async-get-fn — the 11-arg arity is the minimum that
  actually threads async-get-fn through (kotobase-peer.core/fold!, see its
  own arities). Fewer args silently falls back to the sync `with-blocks`
  trampoline via nil defaults — no error, no warning, just slow (this is
  exactly how the bug shipped the first time)."
  11)

(defn- balanced-form
  "From `text` starting at the '(' at `start`, return the full balanced
  form as a string. Naive (doesn't understand strings/chars containing
  parens) — adequate for this codebase's call sites; a form the scanner
  can't balance throws rather than silently mis-scanning."
  [text start]
  (loop [i start depth 0]
    (if (>= i (count text))
      (throw (ex-info "unbalanced parens scanning eng/fold! call" {:start start}))
      (let [c (nth text i)
            depth' (cond (= c \() (inc depth) (= c \)) (dec depth) :else depth)]
        (if (and (zero? depth') (= c \)))
          (subs text start (inc i))
          (recur (inc i) depth'))))))

(defn- fold-call-arg-count
  "Reader-based, not hand-rolled tokenizing: parse the balanced form as
  real EDN/Clojure data and count its arguments. `#js`/`^js` etc. never
  appear inside a fold! call in this file, so plain cljs.reader suffices."
  [form-str]
  (count (rest (reader/read-string form-str))))

(defn- lint-file [path]
  (let [text (str (fs/readFileSync path "utf8"))]
    (loop [idx 0 problems []]
      (let [found (str/index-of text "(eng/fold!" idx)]
        (if (nil? found)
          problems
          (let [form (balanced-form text found)
                n-args (fold-call-arg-count form)
                problems' (if (< n-args min-fold-args)
                            (conj problems {:file path :n-args n-args
                                            :snippet (subs form 0 (min 80 (count form)))})
                            problems)]
            (recur (+ found (count form)) problems')))))))

(defn -main []
  (let [all-problems (mapcat lint-file target-files)]
    (if (seq all-problems)
      (do
        (println "lint_engine_calls: FAIL —" (count all-problems) "eng/fold! call(s) missing :async-get-fn")
        (doseq [{:keys [file n-args snippet]} all-problems]
          (println (str "  " file ": " n-args " args (need >= " min-fold-args ") — " snippet "...")))
        (println "  See kotoba-lang/kotobase-protocols-worker#1 / ADR-2607189000 addendum 2.")
        (set! (.-exitCode js/process) 1))
      (println "lint_engine_calls: OK — every eng/fold! call threads :async-get-fn"))))

(-main)
