(defpackage #:crypto-kit
  (:use #:cl)
  (:export #:digest #:make-digest #:digest-update #:digest-copy #:digest-final
           #:digest-length #:hmac #:hkdf-extract #:hkdf-expand
           #:rsa-verify-pkcs1-v1_5 #:rsa-verify-pss
           #:verify-rsa-pkcs1-v1_5 #:verify-rsa-pss
           #:constant-time-equal #:random-octets #:aes-encrypt-block
           #:aes-128 #:aes-192 #:aes-256
           #:chacha20-keystream #:aead-seal #:aead-open
           #:aead-authentication-failure #:crypto-error
           #:crypto-error-message))
