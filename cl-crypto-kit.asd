(in-package #:asdf-user)

(asdf:defsystem "cl-crypto-kit"
  :description "Hash, HMAC, and HKDF primitives."
  :author "nerima-lisp" :license "MIT" :version "0.1.0"
  :depends-on () :pathname "src" :serial t
  :components ((:file "package") (:file "conditions") (:file "hash")
               (:file "hmac-hkdf"))
  :in-order-to ((test-op (test-op "cl-crypto-kit/test"))))

(asdf:defsystem "cl-crypto-kit/test"
  :depends-on ("cl-crypto-kit" "cl-weave") :pathname "t" :serial t
  :components ((:file "package") (:file "tests-hash") (:file "runner"))
  :perform (asdf:test-op (op c) (declare (ignore op c))
             (uiop:symbol-call "CRYPTO-KIT/TEST" "RUN-TESTS")))
