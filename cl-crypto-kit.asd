(in-package #:asdf-user)

(asdf:defsystem "cl-crypto-kit"
  :description "Pure Common Lisp cryptographic primitives."
  :author "nerima-lisp" :license "MIT" :version "0.1.0"
  :homepage "https://github.com/nerima-lisp/cl-crypto-kit"
  :source-control "https://github.com/nerima-lisp/cl-crypto-kit.git"
  :depends-on () :pathname "src" :serial t
  :components ((:file "package") (:file "conditions") (:file "hash")
               (:file "hmac-hkdf") (:file "aes-sbox") (:file "aes") (:file "gcm")
               (:file "chacha20") (:file "poly1305") (:file "chacha20-poly1305")
               (:file "csprng") (:file "curve25519") (:file "ed25519")
               (:file "rsa") (:file "rsa-pss")
               (:file "p256") (:file "p384") (:file "ecdsa") (:file "api"))
  :in-order-to ((test-op (test-op "cl-crypto-kit/test"))))

(asdf:defsystem "cl-crypto-kit/test"
  :depends-on ("cl-crypto-kit" "cl-weave") :pathname "t" :serial t
  :components ((:file "package") (:file "runner") (:file "tests")
               (:file "tests-hash") (:file "nist-shavs")
               (:file "tests-aes-gcm") (:file "wycheproof-aes-gcm")
               (:file "wycheproof-chacha") (:file "tests-chacha")
               (:file "tests-curve25519") (:file "wycheproof-curve25519")
               (:file "tests-rsa") (:file "tests-ec"))
  :perform (asdf:test-op (op c) (declare (ignore op c))
             (uiop:symbol-call "CRYPTO-KIT/TEST" "RUN-TESTS")))
