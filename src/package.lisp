(defpackage #:crypto-kit
  (:use #:cl)
  (:export #:digest #:make-digest #:digest-update #:digest-copy #:digest-final
           #:digest-length #:hmac #:hkdf-extract #:hkdf-expand
           #:constant-time-equal #:random-octets #:aes-encrypt-block
           #:chacha20-keystream #:aead-seal #:aead-open
           #:aead-authentication-failure #:crypto-error
           #:crypto-error-message))
