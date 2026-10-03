(in-package #:crypto-kit/test)

(defun hex (string)
  (let ((bytes (make-array (truncate (length string) 2)
                           :element-type '(unsigned-byte 8))))
    (dotimes (index (length bytes) bytes)
      (setf (aref bytes index)
            (parse-integer string :start (* index 2)
                           :end (+ (* index 2) 2) :radix 16)))))

(defun ascii (string)
  (map '(vector (unsigned-byte 8)) #'char-code string))

;;; RFC 8439 vectors for the ChaCha20-Poly1305 family.  Wycheproof vectors are
;;; stored as Lisp constants in wycheproof-chacha.lisp so test execution has
;;; no JSON or network dependency.

(defun %chacha-hex (string)
  (let ((out (make-array (/ (length string) 2)
                         :element-type '(unsigned-byte 8))))
    (dotimes (index (length out) out)
      (setf (aref out index)
            (parse-integer string :start (* index 2) :end (+ (* index 2) 2)
                           :radix 16)))))

(defun %chacha-ascii (string)
  (map '(vector (unsigned-byte 8)) #'char-code string))

(defun %chacha-check (condition label)
  (unless condition (error "~A" label))
  t)

(defun %chacha-check-hex (actual expected label)
  (%chacha-check (equalp actual (%chacha-hex expected)) label))

(defun %chacha-call (name &rest arguments)
  (let ((symbol (find-symbol name :crypto-kit)))
    (%chacha-check (and symbol (fboundp symbol))
                   (format nil "missing crypto-kit::~A" name))
    (apply (symbol-function symbol) arguments)))

(defun run-chacha-tests ()
  (let ((checks 0))
    (flet ((check (condition label)
             (incf checks)
             (%chacha-check condition label))
           (check-hex (actual expected label)
             (incf checks)
             (%chacha-check-hex actual expected label)))
      ;; RFC 8439, section 2.4.2: ChaCha20 block 1 / first keystream block.
      (check-hex
       (chacha20-keystream
        (%chacha-hex "000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f")
        1
        (%chacha-hex "000000090000004a00000000")
        64)
       "10f1e7e4d13b5915500fdd1fa32071c4c7d1f4c733c068030422aa9ac3d46c4ed2826446079faa0914c2d705d98b02a2b5129cd1de164eb9cbd083e8a2503c4e"
       "RFC 8439 ChaCha20 keystream")

      ;; Exercise several blocks and a non-block-aligned tail.  The split
      ;; comparison catches counter, block-boundary, and partial-copy errors.
      (let* ((key (%chacha-hex "000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f"))
             (nonce (%chacha-hex "000000090000004a00000000"))
             (long (chacha20-keystream key 1 nonce 4097)))
        (check (= 4097 (length long)) "ChaCha20 long output length")
        (check (equalp (subseq long 0 64)
                       (chacha20-keystream key 1 nonce 64))
               "ChaCha20 long output first block")
        (check (equalp (subseq long 64 4096)
                       (chacha20-keystream key 2 nonce 4032))
               "ChaCha20 long output middle blocks")
        (check (equalp (subseq long 4096)
                       (chacha20-keystream key 65 nonce 1))
               "ChaCha20 long output final byte"))

      ;; RFC 8439, section 2.5.2.
      (check-hex
       (%chacha-call "POLY1305"
                     (%chacha-hex "85d6be7857556d337f4452fe42d506a80103808afb0db2fd4abff6af4149f51b")
                     (%chacha-ascii "Cryptographic Forum Research Group"))
       "a8061dc1305136c6c22b8baf0c0127a9"
       "RFC 8439 Poly1305")

      ;; RFC 8439, section 2.8.2.
      (let* ((key (%chacha-hex "808182838485868788898a8b8c8d8e8f909192939495969798999a9b9c9d9e9f"))
             (nonce (%chacha-hex "070000004041424344454647"))
             (aad (%chacha-hex "50515253c0c1c2c3c4c5c6c7"))
             (plaintext (%chacha-ascii "Ladies and Gentlemen of the class of '99: If I could offer you only one tip for the future, sunscreen would be it."))
             (expected
               (%chacha-hex "d31a8d34648e60db7b86afbc53ef7ec2a4aded51296e08fea9e2b5a736ee62d63dbea45e8ca9671282fafb69da92728b1a71de0a9e060b2905d6a5b67ecd3b3692ddbd7f2d778b8c9803aee328091b58fab324e4fad675945585808b4831d7bc3ff4def08e4b7a9de576d26586cec64b61161ae10b594f09e26a7e902ecbd0600691"))
             (sealed (aead-seal :chacha20-poly1305 key nonce plaintext aad)))
        (check (equalp sealed expected) "RFC 8439 AEAD ciphertext and tag")
        (check (equalp (aead-open :chacha20-poly1305 key nonce sealed aad) plaintext)
               "RFC 8439 AEAD decryption")
        (let ((tampered (copy-seq sealed)))
          (setf (aref tampered 0) (logxor (aref tampered 0) 1))
          (handler-case
              (progn (aead-open :chacha20-poly1305 key nonce tampered aad)
                     (error "AEAD accepted modified ciphertext"))
            (aead-authentication-failure () (incf checks))))
        (let ((tampered (copy-seq sealed)))
          (setf (aref tampered (1- (length tampered)))
                (logxor (aref tampered (1- (length tampered))) 1))
          (handler-case
              (progn (aead-open :chacha20-poly1305 key nonce tampered aad)
                     (error "AEAD accepted modified tag"))
            (aead-authentication-failure () (incf checks))))
        (let ((tampered-aad (copy-seq aad)))
          (setf (aref tampered-aad 0) (logxor (aref tampered-aad 0) 1))
          (handler-case
              (progn (aead-open :chacha20-poly1305 key nonce sealed tampered-aad)
                     (error "AEAD accepted modified AAD"))
            (aead-authentication-failure () (incf checks))))
        (let ((tampered-nonce (copy-seq nonce)))
          (setf (aref tampered-nonce 0) (logxor (aref tampered-nonce 0) 1))
          (handler-case
              (progn (aead-open :chacha20-poly1305 key tampered-nonce sealed aad)
                     (error "AEAD accepted modified nonce"))
            (aead-authentication-failure () (incf checks))))
        (let ((empty-sealed (aead-seal :chacha20-poly1305 key nonce #() aad)))
          (check (= 16 (length empty-sealed)) "ChaCha20-Poly1305 empty seal length")
          (check (equalp (aead-open :chacha20-poly1305 key nonce empty-sealed aad) #())
                 "ChaCha20-Poly1305 empty round-trip")))

      ;; A long, non-aligned AEAD message must round-trip without truncation.
      (let* ((key (make-array 32 :element-type '(unsigned-byte 8)
                              :initial-element #xa5))
             (nonce (make-array 12 :element-type '(unsigned-byte 8)
                               :initial-element #x5a))
             (aad (%chacha-ascii "long-aad"))
             (plaintext (make-array 8193 :element-type '(unsigned-byte 8))))
        (dotimes (i (length plaintext))
          (setf (aref plaintext i) (mod (+ (* i 29) 7) 256)))
        (check (equalp (aead-open :chacha20-poly1305 key nonce
                                  (aead-seal :chacha20-poly1305 key nonce plaintext aad)
                                  aad)
                       plaintext)
               "ChaCha20-Poly1305 long input round-trip")))
    (format t "cl-crypto-kit: ChaCha20/Poly1305 tests passed (~D checks)~%" checks)
    t))

(defun run-wycheproof-chacha-tests ()
  (let ((valid 0) (invalid 0) (malformed 0))
    (dolist (test +wycheproof-chacha-vectors+)
      (destructuring-bind (tc-id result key nonce aad message ciphertext tag) test
        (let ((key (%chacha-hex key))
              (nonce (%chacha-hex nonce))
              (aad (%chacha-hex aad))
              (message (%chacha-hex message)))
          (ecase result
            (:valid
             (incf valid)
             (let* ((expected (concatenate '(vector (unsigned-byte 8))
                                           (%chacha-hex ciphertext) (%chacha-hex tag)))
                    (sealed (aead-seal :chacha20-poly1305 key nonce message aad)))
               (%chacha-check (equalp sealed expected) "Wycheproof seal")
               (%chacha-check (equalp (aead-open :chacha20-poly1305 key nonce sealed aad)
                                      message)
                              "Wycheproof open")))
            (:invalid
             (incf invalid)
             (let ((sealed (concatenate '(vector (unsigned-byte 8))
                                        (%chacha-hex ciphertext) (%chacha-hex tag)))
                   (malformed-p (or (/= (length key) 32)
                                    (/= (length nonce) 12))))
               (if malformed-p
                   (progn
                     (incf malformed)
                     (let ((caught nil))
                       (handler-case
                           (progn
                             (aead-open :chacha20-poly1305 key nonce sealed aad)
                             (error "Wycheproof accepted malformed invalid case ~D"
                                    tc-id))
                         (crypto-error () (setf caught t)))
                       (%chacha-check caught
                                      (format nil
                                              "Wycheproof malformed case ~D did not signal crypto-error"
                                              tc-id))))
                   (let ((caught nil))
                     (handler-case
                         (progn
                           (aead-open :chacha20-poly1305 key nonce sealed aad)
                           (error "Wycheproof accepted invalid case ~D" tc-id))
                       (aead-authentication-failure () (setf caught t)))
                     (%chacha-check caught
                                    (format nil
                                            "Wycheproof invalid case ~D did not signal authentication failure"
                                            tc-id))))))))))
    (%chacha-check (= valid 256) "Unexpected Wycheproof valid case count")
    (%chacha-check (= invalid 69) "Unexpected Wycheproof invalid case count")
    (%chacha-check (= (+ valid invalid) 325)
                   "Unexpected Wycheproof total case count")
    (%chacha-check (= malformed 9)
                   "Unexpected Wycheproof malformed case count")
    (format t
            "cl-crypto-kit: Wycheproof ChaCha20-Poly1305 passed (~D total: ~D valid, ~D invalid, ~D malformed)~%"
            (+ valid invalid) valid invalid malformed)
    t))

(export 'run-chacha-tests)
