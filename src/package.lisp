(defpackage #:crypto-kit
  (:use #:cl)
  (:export #:digest #:make-digest #:digest-update #:digest-copy #:digest-final
           #:digest-length #:hmac #:hkdf-extract #:hkdf-expand
           #:constant-time-equal #:random-octets #:crypto-error
           #:crypto-error-message))
