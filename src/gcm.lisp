(in-package #:crypto-kit)

(define-condition aead-authentication-failure (error) ())

(defun %gcm-xor-into (out in)
  (dotimes (index (length in) out)
    (setf (aref out index) (logxor (aref out index) (aref in index)))))

(defun %gcm-mul (x y)
  (let ((z 0) (v x))
    (dotimes (index 128 z)
      (let ((mask (- (logand (ash y (- (- 127 index))) 1))))
        (setf z (logxor z (logand v mask))
              v (logxor (ash v -1)
                        (logand #xe1000000000000000000000000000000
                                (- (logand v 1)))))))))

(defun %gcm-int (octets)
  (loop for octet across octets
        for value = 0 then (logior (ash value 8) octet)
        finally (return value)))

(defun %gcm-bytes (value size)
  (let ((octets (make-array size :element-type '(unsigned-byte 8))))
    (dotimes (index size octets)
      (setf (aref octets (- size index 1))
            (logand #xff (ash value (* -8 index)))))))

(defun %gcm-ghash (hash-key aad ciphertext)
  (let ((y 0) (hash-key (%gcm-int hash-key)))
    (dolist (data (list aad ciphertext))
      (loop for position from 0 below (length data) by 16
            do (let ((block (make-array 16 :element-type '(unsigned-byte 8)
                                         :initial-element 0)))
                 (replace block data :start2 position
                          :end2 (min (length data) (+ position 16)))
                 (setf y (%gcm-mul (logxor y (%gcm-int block)) hash-key)))))
    (setf y (%gcm-mul
             (logxor y (ash (* 8 (length aad)) 64)
                     (* 8 (length ciphertext)))
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
        (setf y (%gcm-mul (logxor y (* 8 (length nonce))) hash-key))
        (%gcm-bytes y 16))))

(defun %gcm-inc32 (counter)
  (let ((result (copy-seq counter)))
    (loop for index downfrom 15 to 12
          do (incf (aref result index))
             (when (< (aref result index) 256) (return)))
    result))

(defun %gcm-ctr (cipher j0 input)
  (let ((output (make-array (length input) :element-type '(unsigned-byte 8)))
        (counter j0))
    (loop for position from 0 below (length input) by 16
          do (setf counter (%gcm-inc32 counter))
             (let ((stream (aes-encrypt-block cipher counter)))
               (dotimes (index (min 16 (- (length input) position)))
                 (setf (aref output (+ position index))
                               (logxor (aref input (+ position index))
                                       (aref stream index))))))
    output))

(defun %gcm-constant-time-equal (left right)
  (if (/= (length left) (length right)) nil
      (let ((difference 0))
        (dotimes (index (length left) (zerop difference))
          (setf difference (logior difference
                                   (logxor (aref left index)
                                           (aref right index))))))))

(defun %gcm-authenticate (cipher nonce aad ciphertext)
  (let* ((zero (make-array 16 :element-type '(unsigned-byte 8)
                           :initial-element 0))
         (hash-key (aes-encrypt-block cipher zero))
         (j0 (%gcm-j0 hash-key nonce))
         (tag (aes-encrypt-block cipher j0)))
    (%gcm-xor-into tag (%gcm-ghash hash-key aad ciphertext))
    (values j0 tag)))

(defun aead-seal (algorithm key nonce plaintext aad)
  "Return AES-GCM ciphertext concatenated with its 16-octet tag."
  (unless (member algorithm '(:aes-128-gcm :aes-256-gcm))
    (error "Unsupported AEAD algorithm: ~S" algorithm))
  (unless (= (length key) (if (eq algorithm :aes-128-gcm) 16 32))
    (error "AEAD key length does not match the selected algorithm."))
  (let ((cipher (if (eq algorithm :aes-128-gcm) (aes-128 key) (aes-256 key))))
    (multiple-value-bind (j0 ignored)
        (%gcm-authenticate cipher nonce aad #())
      (declare (ignore ignored))
      (let ((ciphertext (%gcm-ctr cipher j0 plaintext)))
        (multiple-value-bind (unused tag)
            (%gcm-authenticate cipher nonce aad ciphertext)
          (declare (ignore unused))
          (let ((output (make-array (+ (length ciphertext) 16)
                                    :element-type '(unsigned-byte 8))))
            (replace output ciphertext)
            (replace output tag :start1 (length ciphertext))
            output))))))

(defun aead-open (algorithm key nonce ciphertext-and-tag aad)
  "Authenticate and decrypt AES-GCM ciphertext concatenated with its tag."
  (unless (member algorithm '(:aes-128-gcm :aes-256-gcm))
    (error "Unsupported AEAD algorithm: ~S" algorithm))
  (unless (= (length key) (if (eq algorithm :aes-128-gcm) 16 32))
    (error "AEAD key length does not match the selected algorithm."))
  (when (< (length ciphertext-and-tag) 16)
    (error 'aead-authentication-failure))
  (let* ((ciphertext-length (- (length ciphertext-and-tag) 16))
         (ciphertext (subseq ciphertext-and-tag 0 ciphertext-length))
         (received-tag (subseq ciphertext-and-tag ciphertext-length))
         (cipher (if (eq algorithm :aes-128-gcm) (aes-128 key) (aes-256 key))))
    (multiple-value-bind (j0 expected-tag)
        (%gcm-authenticate cipher nonce aad ciphertext)
      (unless (%gcm-constant-time-equal expected-tag received-tag)
        (error 'aead-authentication-failure))
      (%gcm-ctr cipher j0 ciphertext))))
