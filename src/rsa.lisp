(in-package #:crypto-kit)

(defparameter +rsa-digestinfo-prefixes+
  '((:sha1 . #(#x30 #x21 #x30 #x09 #x06 #x05 #x2b #x0e #x03 #x02 #x1a #x05 #x00 #x04 #x14))
    (:sha256 . #(#x30 #x31 #x30 #x0d #x06 #x09 #x60 #x86 #x48 #x01 #x65 #x03 #x04 #x02 #x01 #x05 #x00 #x04 #x20))
    (:sha384 . #(#x30 #x41 #x30 #x0d #x06 #x09 #x60 #x86 #x48 #x01 #x65 #x03 #x04 #x02 #x02 #x05 #x00 #x04 #x30))
    (:sha512 . #(#x30 #x51 #x30 #x0d #x06 #x09 #x60 #x86 #x48 #x01 #x65 #x03 #x04 #x02 #x03 #x05 #x00 #x04 #x40))))

(defun %rsa-octets-integer (octets)
  (read-be octets 0 (length octets)))

(defun %rsa-integer-octets (integer size)
  (when (or (minusp integer) (> integer (1- (ash 1 (* 8 size)))))
    (crypto-error "RSA integer does not fit in ~D octets" size))
  (put-be integer size))

(defun %rsa-validate-public-key (modulus exponent)
  (unless (and (integerp modulus) (integerp exponent)
               (oddp modulus) (oddp exponent) (> exponent 2)
               (<= 2048 (integer-length modulus) 8192)
               (< exponent modulus) (<= exponent #xffffffff))
    (crypto-error "Invalid RSA public key"))
  (values modulus exponent))

(defun %rsa-modexp (base exponent modulus)
  (let ((result 1)
        (base (mod base modulus)))
    (loop for bit downfrom (1- (integer-length exponent)) to 0
          do (setf result (mod (* result result) modulus))
             (when (logbitp bit exponent)
               (setf result (mod (* result base) modulus))))
    result))

(defun %rsa-recover-em (signature modulus exponent)
  (let* ((size (ceiling (integer-length modulus) 8))
         (s (%rsa-octets-integer signature)))
    (unless (= (length signature) size)
      (return-from %rsa-recover-em nil))
    (when (>= s modulus)
      (return-from %rsa-recover-em nil))
    (%rsa-integer-octets (%rsa-modexp s exponent modulus) size)))

(defun %rsa-expected-pkcs1-em (algorithm message size)
  (let* ((prefix (cdr (assoc algorithm +rsa-digestinfo-prefixes+)))
         (hash (digest algorithm message))
         (digest-info (concat-octets prefix hash))
         (padding-length (- size (length digest-info) 3)))
    (when (< padding-length 8)
      (return-from %rsa-expected-pkcs1-em nil))
    (concat-octets #(0 1)
                   (make-array padding-length :element-type '(unsigned-byte 8)
                               :initial-element #xff)
                   #(0) digest-info)))

(defun rsa-verify-pkcs1-v1_5 (algorithm modulus exponent message signature)
  "Verify an RSASSA-PKCS1-v1_5 signature for MESSAGE."
  (%rsa-validate-public-key modulus exponent)
  (unless (member algorithm '(:sha1 :sha256 :sha384 :sha512))
    (crypto-error "Unsupported RSA digest algorithm ~S" algorithm))
  (let ((em (%rsa-recover-em signature modulus exponent)))
    (and em (constant-time-equal em (%rsa-expected-pkcs1-em algorithm message (length em))))))

(defun verify-rsa-pkcs1-v1_5 (&rest arguments)
  (apply #'rsa-verify-pkcs1-v1_5 arguments))
