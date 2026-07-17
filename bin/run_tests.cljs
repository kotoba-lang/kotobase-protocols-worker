;; nbb test runner for the shell's pure logic. Run from the repo root:
;;   nbb --classpath "src:test:../kotobase-protocols/src:../kotobase/src" bin/run_tests.cljs
;; (paths relative to the west checkout orgs/kotoba-lang/; CI clones the
;; two library deps into .deps/ instead.)
(ns run-tests
  (:require [cljs.test :as t]
            [kotobase-protocols-worker.core-test]
            [kotobase-protocols-worker.sigv4-test]))

(defmethod t/report [:cljs.test/default :end-run-tests] [m]
  (when-not (t/successful? m)
    (set! (.-exitCode js/process) 1)))

(t/run-tests 'kotobase-protocols-worker.core-test
             'kotobase-protocols-worker.sigv4-test)
