(in-package #:crypto-kit)

(declaim (inline %gcm-mul)
         (optimize (speed 3) (safety 0) (debug 0)))

(define-condition aead-authentication-failure (error) ())

(defconstant +gcm-max-iv-bits+ (1- (ash 1 64)))
(defconstant +gcm-max-data-bytes+ (- (ash 1 36) 32))
(defconstant +gcm-max-aad-bytes+ (1- (ash 1 61)))

(defun %gcm-check-input-lengths (nonce-length plaintext-length aad-length
                                 &optional ciphertext-length)
  (unless (and (integerp nonce-length)
               (<= 1 (* 8 nonce-length) +gcm-max-iv-bits+))
    (crypto-error "AES-GCM IV length is out of range"))
  (unless (and (integerp plaintext-length)
               (<= 0 plaintext-length +gcm-max-data-bytes+))
    (crypto-error "AES-GCM plaintext is too long"))
  (unless (and (integerp aad-length)
               (<= 0 aad-length +gcm-max-aad-bytes+))
    (crypto-error "AES-GCM AAD is too long"))
  (when (and ciphertext-length
             (or (not (integerp ciphertext-length))
                 (not (<= 0 ciphertext-length +gcm-max-data-bytes+))))
    (crypto-error "AES-GCM ciphertext is too long")))

(defun %gcm-xor-into (out in)
  (dotimes (index (length in) out)
    (setf (aref out index) (logxor (aref out index) (aref in index)))))

(defun %gcm-mul (x y)
  (let ((z 0) (v x))
    (dotimes (index 128 z)
      (let ((mask (- (ldb (byte 1 (- 127 index)) y)))
            (carry (- (logand v 1))))
        (setf z (logxor z (logand v mask))
              v (logxor (ash v -1)
                        (logand #xe1000000000000000000000000000000
                                carry)))))))

(defun %gcm-int (octets)
  (let ((value 0))
    (loop for octet across octets
          do (setf value (logior (ash value 8) octet)))
    value))

(defun %gcm-bytes (value size)
  (let ((octets (make-array size :element-type '(unsigned-byte 8))))
    (dotimes (index size octets)
      (setf (aref octets (- size index 1))
            (logand #xff (ash value (* -8 index)))))))

(defun %gcm-length-block (left-length right-length)
  (%gcm-bytes (logior (ash (* 8 left-length) 64)
                      (* 8 right-length))
              16))

(defun %gcm-ghash (hash-key aad ciphertext)
  (let ((y 0) (hash-key (%gcm-int hash-key))
        (block (make-array 16 :element-type '(unsigned-byte 8)
                           :initial-element 0)))
    (dolist (data (list aad ciphertext))
      (loop for position from 0 below (length data) by 16
            do (fill block 0)
               (replace block data :start2 position
                        :end2 (min (length data) (+ position 16)))
               (setf y (%gcm-mul (logxor y (%gcm-int block)) hash-key))))
    (setf y (%gcm-mul (logxor y
                              (%gcm-int (%gcm-length-block
                                         (length aad) (length ciphertext))))
                      hash-key))
    (%gcm-bytes y 16)))

(defun %gcm-j0 (hash-key nonce)
  (if (= (length nonce) 12)
      (let ((j0 (make-array 16 :element-type '(unsigned-byte 8)
                            :initial-element 0)))
        (replace j0 nonce)
        (setf (aref j0 15) 1)
        j0)
      (let ((y 0) (hash-key (%gcm-int hash-key)))
        (loop for position from 0 below (length nonce) by 16
              do (let ((block (make-array 16 :element-type '(unsigned-byte 8)
                                           :initial-element 0)))
                   (replace block nonce :start2 position
                            :end2 (min (length nonce) (+ position 16)))
                   (setf y (%gcm-mul (logxor y (%gcm-int block)) hash-key))))
        (setf y (%gcm-mul (logxor y
                                  (%gcm-int (%gcm-length-block 0
                                                                 (length nonce))))
                          hash-key))
        (%gcm-bytes y 16))))

(defun %gcm-inc32 (counter)
  (let ((carry 1))
    (loop for index downfrom 15 to 12
          do (let ((value (+ (aref counter index) carry)))
               (setf (aref counter index) (logand #xff value)
                     carry (logand carry (- (ldb (byte 1 8) value)))))))
  counter)

(defun %gcm-ctr (cipher j0 input)
  (let ((output (make-array (length input) :element-type '(unsigned-byte 8)))
        (counter (copy-seq j0))
        (stream (make-array 16 :element-type '(unsigned-byte 8)))
        (planes (make-array 8 :element-type '(unsigned-byte 16)
                            :initial-element 0)))
    (loop for position from 0 below (length input) by 16
          do (setf counter (%gcm-inc32 counter))
             (crypto-kit::%aes-encrypt-block-into cipher counter stream planes)
             (dotimes (index (min 16 (- (length input) position)))
               (setf (aref output (+ position index))
                     (logxor (aref input (+ position index))
                             (aref stream index)))))
    output))

(defun %gcm-constant-time-equal (left right)
  (let ((difference (logxor (length left) (length right))))
    (dotimes (index (max (length left) (length right))
             (zerop difference))
      (setf difference
            (logior difference
                   (if (< index (length left))
                       (logxor (aref left index)
                               (if (< index (length right))
                                   (aref right index) 0))
                       (if (< index (length right))
                           (aref right index) 0)))))))

(defun %gcm-authenticate (cipher nonce aad ciphertext)
  (let* ((zero (make-array 16 :element-type '(unsigned-byte 8)
                           :initial-element 0))
         (hash-key (aes-encrypt-block cipher zero))
         (j0 (%gcm-j0 hash-key nonce))
         (tag (aes-encrypt-block cipher j0)))
    (%gcm-xor-into tag (%gcm-ghash hash-key aad ciphertext))
    (values j0 tag)))

(defun %gcm-context (cipher nonce)
  (let* ((zero (make-array 16 :element-type '(unsigned-byte 8)
                           :initial-element 0))
         (hash-key (aes-encrypt-block cipher zero)))
    (values hash-key (%gcm-j0 hash-key nonce))))

(defun %aes-gcm-aead-seal (algorithm key nonce plaintext aad)
  "Return AES-GCM ciphertext concatenated with its 16-octet tag."
  (unless (member algorithm '(:aes-128-gcm :aes-192-gcm :aes-256-gcm))
    (error "Unsupported AEAD algorithm: ~S" algorithm))
  (unless (= (length key) (ecase algorithm (:aes-128-gcm 16) (:aes-192-gcm 24) (:aes-256-gcm 32)))
    (error "AEAD key length does not match the selected algorithm."))
  (%gcm-check-input-lengths (length nonce) (length plaintext) (length aad))
  (let ((cipher (ecase algorithm (:aes-128-gcm (aes-128 key)) (:aes-192-gcm (aes-192 key)) (:aes-256-gcm (aes-256 key)))))
    (multiple-value-bind (hash-key j0) (%gcm-context cipher nonce)
      (let ((ciphertext (%gcm-ctr cipher j0 plaintext)))
        (let ((tag (aes-encrypt-block cipher j0))
              (output (make-array (+ (length ciphertext) 16)
                                  :element-type '(unsigned-byte 8))))
          (%gcm-xor-into tag (%gcm-ghash hash-key aad ciphertext))
          (replace output ciphertext)
          (replace output tag :start1 (length ciphertext))
          output)))))

(defun %aes-gcm-aead-open (algorithm key nonce ciphertext-and-tag aad)
  "Authenticate and decrypt AES-GCM ciphertext concatenated with its tag."
  (unless (member algorithm '(:aes-128-gcm :aes-192-gcm :aes-256-gcm))
    (error "Unsupported AEAD algorithm: ~S" algorithm))
  (unless (= (length key) (ecase algorithm (:aes-128-gcm 16) (:aes-192-gcm 24) (:aes-256-gcm 32)))
    (error "AEAD key length does not match the selected algorithm."))
  (when (< (length ciphertext-and-tag) 16)
    (error 'aead-authentication-failure))
  (let* ((ciphertext-length (- (length ciphertext-and-tag) 16))
         (cipher (ecase algorithm (:aes-128-gcm (aes-128 key)) (:aes-192-gcm (aes-192 key)) (:aes-256-gcm (aes-256 key)))))
    (%gcm-check-input-lengths (length nonce) 0 (length aad) ciphertext-length)
    (let ((ciphertext (subseq ciphertext-and-tag 0 ciphertext-length))
          (received-tag (subseq ciphertext-and-tag ciphertext-length)))
      (multiple-value-bind (hash-key j0) (%gcm-context cipher nonce)
        (let ((expected-tag (aes-encrypt-block cipher j0)))
          (%gcm-xor-into expected-tag (%gcm-ghash hash-key aad ciphertext))
          (unless (%gcm-constant-time-equal expected-tag received-tag)
            (error 'aead-authentication-failure))
          (%gcm-ctr cipher j0 ciphertext))))))
