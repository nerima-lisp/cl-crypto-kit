(defpackage #:crypto-kit
  (:use #:cl)
  (:export #:digest #:make-digest #:digest-update #:digest-copy #:digest-final
           #:digest-length #:hmac #:hkdf-extract #:hkdf-expand
           #:constant-time-equal #:random-octets #:aes-encrypt-block
           #:aes-128 #:aes-192 #:aes-256
           #:chacha20-keystream #:aead-seal #:aead-open
           #:p256-ecdh #:p384-point-on-curve-p #:ecdsa-verify
           #:ecdsa-verify-p256 #:ecdsa-verify-p384
           #:aead-authentication-failure #:crypto-error
           #:crypto-error-message))
