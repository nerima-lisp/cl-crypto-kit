(in-package #:crypto-kit)

;; Keep the AES-GCM implementation supplied by gcm.lisp reachable after this
;; file installs the algorithm-dispatching definitions below.
(defun %chacha-xor (left right)
  (let ((result (make-array (length left) :element-type '(unsigned-byte 8))))
    (dotimes (index (length left) result)
      (setf (aref result index) (logxor (aref left index) (aref right index))))))

(defun %le64 (value)
  (let ((result (make-array 8 :element-type '(unsigned-byte 8))))
    (dotimes (index 8 result)
      (setf (aref result index) (logand #xff (ash value (* -8 index)))))))

(defun %pad16 (octets)
  (let ((padding (mod (- 16 (mod (length octets) 16)) 16)))
    (if (zerop padding)
        #()
        (make-array padding :element-type '(unsigned-byte 8)
                    :initial-element 0))))

(defun %chacha-aead-mac-data (aad ciphertext)
  (concatenate '(vector (unsigned-byte 8))
               aad (%pad16 aad) ciphertext (%pad16 ciphertext)
               (%le64 (length aad)) (%le64 (length ciphertext))))

(defun %poly1305-mac (key data)
  (poly1305 key data))

(defun %chacha-aead-seal (key nonce plaintext aad)
  (let* ((one-time-key (subseq (%chacha-block key 0 nonce) 0 32))
         (ciphertext (%chacha-xor plaintext
                                  (chacha20-keystream key 1 nonce (length plaintext))))
         (tag (%poly1305-mac one-time-key
                             (%chacha-aead-mac-data aad ciphertext)))
         (result (make-array (+ (length ciphertext) (length tag))
                             :element-type '(unsigned-byte 8))))
    (unless (= (length tag) 16)
      (crypto-error "Poly1305 must return a 16-octet tag"))
    (replace result ciphertext)
    (replace result tag :start1 (length ciphertext))
    result))

(defun %chacha-aead-open (key nonce ciphertext-and-tag aad)
  (when (< (length ciphertext-and-tag) 16)
    (error 'aead-authentication-failure))
  (let* ((ciphertext-length (- (length ciphertext-and-tag) 16))
         (ciphertext (subseq ciphertext-and-tag 0 ciphertext-length))
         (received-tag (subseq ciphertext-and-tag ciphertext-length))
         (one-time-key (subseq (%chacha-block key 0 nonce) 0 32))
         (expected-tag (%poly1305-mac one-time-key
                                      (%chacha-aead-mac-data aad ciphertext))))
    (unless (and (= (length expected-tag) 16)
                 (constant-time-equal expected-tag received-tag))
      (error 'aead-authentication-failure))
    (%chacha-xor ciphertext
                 (chacha20-keystream key 1 nonce (length ciphertext)))))

(defun aead-seal (algorithm key nonce plaintext aad)
  (case algorithm
    (:chacha20-poly1305
     (unless (= (length key) 32)
       (crypto-error "ChaCha20-Poly1305 requires a 32-octet key"))
     (unless (= (length nonce) 12)
       (crypto-error "ChaCha20-Poly1305 requires a 12-octet nonce"))
     (unless (<= (length plaintext) +chacha20-max-bytes+)
       (crypto-error "ChaCha20-Poly1305 plaintext is too long"))
     (%chacha-aead-seal key nonce plaintext aad))
    ((:aes-128-gcm :aes-192-gcm :aes-256-gcm)
     (%aes-gcm-aead-seal algorithm key nonce plaintext aad))
    (otherwise (error "Unsupported AEAD algorithm: ~S" algorithm))))

(defun aead-open (algorithm key nonce ciphertext-and-tag aad)
  (case algorithm
    (:chacha20-poly1305
     (unless (= (length key) 32)
       (crypto-error "ChaCha20-Poly1305 requires a 32-octet key"))
     (unless (= (length nonce) 12)
       (crypto-error "ChaCha20-Poly1305 requires a 12-octet nonce"))
     (when (and (>= (length ciphertext-and-tag) 16)
                (> (- (length ciphertext-and-tag) 16) +chacha20-max-bytes+))
       (crypto-error "ChaCha20-Poly1305 ciphertext is too long"))
     (%chacha-aead-open key nonce ciphertext-and-tag aad))
    ((:aes-128-gcm :aes-192-gcm :aes-256-gcm)
     (%aes-gcm-aead-open algorithm key nonce ciphertext-and-tag aad))
    (otherwise (error "Unsupported AEAD algorithm: ~S" algorithm))))
