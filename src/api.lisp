(in-package #:crypto-kit)

(defstruct (rsa-public-key (:constructor make-rsa-public-key (modulus exponent)))
  modulus exponent)

(defstruct (ec-public-key (:constructor make-ec-public-key (curve point)))
  curve point)

(defstruct (ed25519-public-key (:constructor make-ed25519-public-key (octets)))
  octets)

(defun p256-generate-keypair ()
  (let ((scalar nil))
    (dotimes (attempt 128)
      (let ((candidate (ec-octets-int (random-octets 32))))
        (when (and (> candidate 0) (< candidate (ec-curve-n +p256+)))
          (setf scalar candidate)
          (return))))
    (unless scalar
      (error 'csprng-error
             :message "Could not sample a P-256 private scalar"))
    (values (ec-int-octets scalar 32)
            (ec-encode-point (ec-mul scalar
                                      (ec-point (ec-curve-gx +p256+)
                                                (ec-curve-gy +p256+))
                                      +p256+ :fixed 256)
                              +p256+))))

(defun %public-key-value (key type)
  (if (typep key type) key (error 'crypto-error :message "Invalid public key")))

(defun verify-signature (scheme public-key message signature)
  (case scheme
    ((:ecdsa-p256-sha256 :ecdsa-p384-sha384)
     (let* ((key (%public-key-value public-key 'ec-public-key))
            (point (ec-public-key-point key)))
       (ecase scheme
         (:ecdsa-p256-sha256 (ecdsa-verify-p256 message point signature))
         (:ecdsa-p384-sha384 (ecdsa-verify-p384 message point signature)))))
    ((:rsa-pkcs1-sha256 :rsa-pkcs1-sha384 :rsa-pkcs1-sha512)
     (let ((key (%public-key-value public-key 'rsa-public-key)))
       (rsa-verify-pkcs1-v1_5
        (ecase scheme
          (:rsa-pkcs1-sha256 :sha256)
          (:rsa-pkcs1-sha384 :sha384)
          (:rsa-pkcs1-sha512 :sha512))
        (rsa-public-key-modulus key) (rsa-public-key-exponent key)
        message signature)))
    ((:rsa-pss-rsae-sha256 :rsa-pss-rsae-sha384 :rsa-pss-rsae-sha512)
     (let ((key (%public-key-value public-key 'rsa-public-key)))
       (rsa-verify-pss
        (ecase scheme
          (:rsa-pss-rsae-sha256 :sha256)
          (:rsa-pss-rsae-sha384 :sha384)
          (:rsa-pss-rsae-sha512 :sha512))
        (rsa-public-key-modulus key) (rsa-public-key-exponent key)
        message signature)))
    (:ed25519
     (let ((key (%public-key-value public-key 'ed25519-public-key)))
       (ed25519-verify signature message (ed25519-public-key-octets key))))
    (otherwise (error 'crypto-error :message "Unsupported signature scheme"))))
