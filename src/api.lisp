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
    (let ((private-octets (ec-int-octets scalar 32)))
      (values private-octets
              (%ec-public-from-scalar +p256+ private-octets)))))

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
(defclass ec-private-key ()
  ((scalar :initarg :scalar :reader %ec-private-key-scalar)))

(defclass ed25519-private-key ()
  ((seed :initarg :seed :reader %ed25519-private-key-seed)
   (public-key-octets :initarg :public-key-octets
                      :reader %ed25519-private-key-public-key)))

(defmethod print-object ((key ec-private-key) stream)
  (print-unreadable-object (key stream :type t)
    (write-string "[REDACTED]" stream)))
(defmethod describe-object ((key ec-private-key) stream)
  (declare (ignore key))
  (format stream "~&EC private key; material redacted.~%"))

(defmethod print-object ((key ed25519-private-key) stream)
  (print-unreadable-object (key stream :type t)
    (write-string "[REDACTED]" stream)))
(defmethod describe-object ((key ed25519-private-key) stream)
  (declare (ignore key))
  (format stream "~&Ed25519 private key; material redacted.~%"))

(defun make-ec-private-key (curve scalar-octets)
  (unless (member curve '(:p256 p256))
    (error 'crypto-error :message "Only P-256 private keys are supported"))
  (multiple-value-bind (safe-scalar valid)
      (%ec-private-scalar scalar-octets +p256+)
    (declare (ignore safe-scalar))
    (unless (= valid 1)
      (error 'crypto-error :message "Invalid P-256 private scalar"))
    (make-instance 'ec-private-key :scalar (copy-seq scalar-octets))))

(defun make-ed25519-private-key (seed)
  (unless (and (typep seed '(vector (unsigned-byte 8)))
               (= (length seed) 32))
    (error 'crypto-error :message "Ed25519 seed must contain 32 octets"))
  (let* ((seed-copy (copy-seq seed))
         (public-key (ed25519-public-key-from-seed seed-copy)))
    (make-instance 'ed25519-private-key
                   :seed seed-copy
                   :public-key-octets public-key)))

(defgeneric private-key-public-key (private-key))

(defmethod private-key-public-key ((private-key ec-private-key))
  (make-ec-public-key
   :p256
   (%ec-public-from-scalar +p256+ (%ec-private-key-scalar private-key))))

(defmethod private-key-public-key ((private-key ed25519-private-key))
  (make-ed25519-public-key
   (copy-seq (%ed25519-private-key-public-key private-key))))

(defmethod private-key-public-key ((private-key t))
  (declare (ignore private-key))
  (error 'crypto-error :message "Unsupported private key type"))

(defun sign-message (scheme private-key message)
  (case scheme
    (:ecdsa-p256-sha256
     (unless (typep private-key 'ec-private-key)
       (error 'crypto-error :message
              "ECDSA P-256 requires a P-256 private key"))
     (ecdsa-sign-p256 message (%ec-private-key-scalar private-key)))
    (:ed25519
     (unless (typep message '(vector (unsigned-byte 8)))
       (error 'crypto-error :message
              "Ed25519 message must be an octet vector"))
     (unless (typep private-key 'ed25519-private-key)
       (error 'crypto-error :message
              "Ed25519 requires an Ed25519 private key"))
     (ed25519-sign (%ed25519-private-key-seed private-key)
                   message
                   (%ed25519-private-key-public-key private-key)))
    (otherwise
     (error 'crypto-error :message "Unsupported signature scheme"))))
