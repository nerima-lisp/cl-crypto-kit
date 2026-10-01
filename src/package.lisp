(defpackage #:crypto-kit
  (:use #:cl)
  (:export #:digest #:make-digest #:digest-update #:digest-copy #:digest-final
           #:digest-length #:hmac #:hkdf-extract #:hkdf-expand
           #:constant-time-equal #:random-octets #:aes-encrypt-block
           #:aes-128 #:aes-192 #:aes-256
           #:chacha20-keystream #:aead-seal #:aead-open
           #:aead-authentication-failure #:crypto-error
           #:crypto-error-message #:csprng-error
           #:csprng-error-message #:x25519 #:ed25519-public-key
           #:ed25519-sign #:ed25519-verify #:ed25519-generate-keypair))
