(in-package #:crypto-kit/test)

(defun %aes-gcm-bytes (hex)
  (let ((result (make-array (/ (length hex) 2)
                            :element-type '(unsigned-byte 8))))
    (dotimes (index (length result) result)
      (setf (aref result index)
            (parse-integer hex :start (* index 2) :end (+ (* index 2) 2)
                           :radix 16)))))

(defun %aes-gcm-check (actual expected label)
  (unless (equalp actual expected)
    (error "~A: got ~S, expected ~S" label actual expected)))

(defun run-aes-gcm-tests ()
  (%aes-gcm-check
   (crypto-kit::aes-encrypt-block
    (%aes-gcm-bytes "000102030405060708090a0b0c0d0e0f")
    (%aes-gcm-bytes "00112233445566778899aabbccddeeff"))
   (%aes-gcm-bytes "69c4e0d86a7b0430d8cdb78070b4c55a")
   "FIPS-197 AES-128")
  (%aes-gcm-check
   (crypto-kit::aes-encrypt-block
    (%aes-gcm-bytes "000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f")
    (%aes-gcm-bytes "00112233445566778899aabbccddeeff"))
   (%aes-gcm-bytes "8ea2b7ca516745bfeafc49904b496089")
   "FIPS-197 AES-256")
  (%aes-gcm-check
   (crypto-kit::aes-encrypt-block
    (crypto-kit::%aes-make
     (%aes-gcm-bytes "000102030405060708090a0b0c0d0e0f1011121314151617")
     24)
    (%aes-gcm-bytes "00112233445566778899aabbccddeeff"))
   (%aes-gcm-bytes "dda97ca4864cdfe06eaf70a0ec0d7191")
   "FIPS-197 AES-192")
  (%aes-gcm-check
   (crypto-kit::aead-seal :aes-128-gcm
              (%aes-gcm-bytes "00000000000000000000000000000000")
              (%aes-gcm-bytes "000000000000000000000000")
              (%aes-gcm-bytes "")
              (%aes-gcm-bytes ""))
   (%aes-gcm-bytes "58e2fccefa7e3061367f1d57a4e7455a")
   "NIST GCM empty")
  (dolist (vector
            '((:aes-128-gcm
               "00000000000000000000000000000000"
               "000000000000000000000000"
               ""
               ""
               "58e2fccefa7e3061367f1d57a4e7455a"
               "McGrew-Viega AES-128 case 1")
              (:aes-128-gcm
               "00000000000000000000000000000000"
               "000000000000000000000000"
               "00000000000000000000000000000000"
               ""
               "0388dace60b6a392f328c2b971b2fe78ab6e47d42cec13bdf53a67b21257bddf"
               "McGrew-Viega AES-128 case 2")
              (:aes-128-gcm
               "feffe9928665731c6d6a8f9467308308"
               "cafebabefacedbaddecaf888"
               "d9313225f88406e5a55909c5aff5269a86a7a9531534f7da2e4c303d8a318a721c3c0c95956809532fcf0e2449a6b525b16aedf5aa0de657ba637b39"
               ""
               "42831ec2217774244b7221b784d0d49ce3aa212f2c02a4e035c17e2329aca12e21d514b25466931c7d8f6a5aac84aa051ba30b396a0aac973d58e091cc15abcc191161501aabab46b8fbac85"
               "McGrew-Viega AES-128 case 3")
              (:aes-128-gcm
               "feffe9928665731c6d6a8f9467308308"
               "cafebabefacedbaddecaf888"
               "d9313225f88406e5a55909c5aff5269a86a7a9531534f7da2e4c303d8a318a721c3c0c95956809532fcf0e2449a6b525b16aedf5aa0de657ba637b39"
               "feedfacedeadbeeffeedfacedeadbeefabaddad2"
               "42831ec2217774244b7221b784d0d49ce3aa212f2c02a4e035c17e2329aca12e21d514b25466931c7d8f6a5aac84aa051ba30b396a0aac973d58e0915bc94fbc3221a5db94fae95ae7121a47"
               "McGrew-Viega AES-128 case 4")
              (:aes-256-gcm
               "0000000000000000000000000000000000000000000000000000000000000000"
               "000000000000000000000000"
               ""
               ""
               "530f8afbc74536b9a963b4f1c4cb738b"
               "McGrew-Viega AES-256 case 13")
              (:aes-256-gcm
               "0000000000000000000000000000000000000000000000000000000000000000"
               "000000000000000000000000"
               "00000000000000000000000000000000"
               ""
               "cea7403d4d606b6e074ec5d3baf39d18d0d1c8a799996bf0265b98b5d48ab919"
               "McGrew-Viega AES-256 case 14")
              (:aes-256-gcm
               "feffe9928665731c6d6a8f9467308308feffe9928665731c6d6a8f9467308308"
               "cafebabefacedbaddecaf888"
               "d9313225f88406e5a55909c5aff5269a86a7a9531534f7da2e4c303d8a318a721c3c0c95956809532fcf0e2449a6b525b16aedf5aa0de657ba637b39"
               ""
               "522dc1f099567d07f47f37a32a84427d643a8cdcbfe5c0c97598a2bd2555d1aa8cb08e48590dbb3da7b08b1056828838c5f61e6393ba7a0abcc9f662eb9f796c8d356fc31a8433884b696f4f"
               "McGrew-Viega AES-256 case 15")
              (:aes-256-gcm
               "feffe9928665731c6d6a8f9467308308feffe9928665731c6d6a8f9467308308"
               "cafebabefacedbaddecaf888"
               "d9313225f88406e5a55909c5aff5269a86a7a9531534f7da2e4c303d8a318a721c3c0c95956809532fcf0e2449a6b525b16aedf5aa0de657ba637b39"
               "feedfacedeadbeeffeedfacedeadbeefabaddad2"
               "522dc1f099567d07f47f37a32a84427d643a8cdcbfe5c0c97598a2bd2555d1aa8cb08e48590dbb3da7b08b1056828838c5f61e6393ba7a0abcc9f66276fc6ece0f4e1768cddf8853bb2d551b"
               "McGrew-Viega AES-256 case 16")))
    (let* ((algorithm (first vector))
           (key (%aes-gcm-bytes (second vector)))
           (nonce (%aes-gcm-bytes (third vector)))
           (plaintext (%aes-gcm-bytes (fourth vector)))
           (aad (%aes-gcm-bytes (fifth vector)))
           (expected (%aes-gcm-bytes (sixth vector)))
           (label (seventh vector))
           (sealed (crypto-kit::aead-seal algorithm key nonce plaintext aad)))
      (%aes-gcm-check sealed expected label)
      (%aes-gcm-check (crypto-kit::aead-open algorithm key nonce sealed aad)
                      plaintext
                      (concatenate 'string label " open"))))
  (let* ((key (%aes-gcm-bytes "00000000000000000000000000000000"))
         (nonce (%aes-gcm-bytes "000000000000000000000000"))
         (plaintext (%aes-gcm-bytes "00000000000000000000000000000000"))
         (aad (%aes-gcm-bytes "feedfacedeadbeef"))
         (sealed (crypto-kit::aead-seal :aes-128-gcm key nonce plaintext aad)))
    (flet ((expect-failure (ciphertext test-nonce test-aad label)
             (handler-case
                 (progn
                   (crypto-kit::aead-open :aes-128-gcm key test-nonce ciphertext test-aad)
                   (error "modified AES-GCM ~A was accepted" label))
               (crypto-kit::aead-authentication-failure () nil))))
      (let ((tampered (copy-seq sealed)))
        (setf (aref tampered 0) (logxor (aref tampered 0) 1))
        (expect-failure tampered nonce aad "ciphertext"))
      (let ((tampered (copy-seq sealed)))
        (setf (aref tampered (1- (length tampered)))
              (logxor (aref tampered (1- (length tampered))) 1))
        (expect-failure tampered nonce aad "tag"))
      (let ((tampered (copy-seq nonce)))
        (setf (aref tampered 0) (logxor (aref tampered 0) 1))
        (expect-failure sealed tampered aad "nonce"))
      (let ((tampered (copy-seq aad)))
        (setf (aref tampered 0) (logxor (aref tampered 0) 1))
        (expect-failure sealed nonce tampered "AAD"))))
  (handler-case
      (progn
        (crypto-kit::aead-open :aes-128-gcm
                               (%aes-gcm-bytes "00000000000000000000000000000000")
                               (%aes-gcm-bytes "000000000000000000000000")
                               (%aes-gcm-bytes "")
                               (%aes-gcm-bytes ""))
        (error "short AES-GCM ciphertext-and-tag was accepted"))
    (crypto-kit::aead-authentication-failure () nil))
  (let ((max-iv-bytes (floor crypto-kit::+gcm-max-iv-bits+ 8))
        (max-data-bytes crypto-kit::+gcm-max-data-bytes+)
        (max-aad-bytes crypto-kit::+gcm-max-aad-bytes+))
    (flet ((length-only-octets (length)
             (make-array length :element-type nil))
           (expect-crypto-error (thunk label)
             (handler-case
                 (progn (funcall thunk)
                        (error "Accepted invalid AES-GCM length: ~A" label))
               (crypto-kit::crypto-error () nil))))
      ;; SBCL's maximum array dimension prevents public construction of 2^61-byte IV/AAD inputs.
      ;; Keep those unrepresentable upper-bound checks on the shared checker.
      (crypto-kit::%gcm-check-input-lengths 1 max-data-bytes max-aad-bytes)
      (crypto-kit::%gcm-check-input-lengths max-iv-bytes 0 0)
      (crypto-kit::%gcm-check-input-lengths 1 0 0 max-data-bytes)
      (expect-crypto-error
       (lambda ()
         (crypto-kit::%gcm-check-input-lengths (1+ max-iv-bytes) 0 0))
       "IV upper boundary")
      (expect-crypto-error
       (lambda ()
         (crypto-kit::%gcm-check-input-lengths 1 0 (1+ max-aad-bytes)))
       "AAD upper boundary")
      (expect-crypto-error
       (lambda ()
         (aead-seal :aes-128-gcm
                    (%aes-gcm-bytes "00000000000000000000000000000000")
                    #() #() #()))
       "zero IV")
      (expect-crypto-error
       (lambda ()
         (aead-seal :aes-128-gcm
                    (%aes-gcm-bytes "00000000000000000000000000000000")
                    #(0) (length-only-octets (1+ max-data-bytes)) #()))
       "plaintext upper boundary")
      (expect-crypto-error
       (lambda ()
         (aead-open :aes-128-gcm
                    (%aes-gcm-bytes "00000000000000000000000000000000")
                    #(0)
                    (length-only-octets (+ 16 (1+ max-data-bytes)))
                    #()))
       "ciphertext upper boundary")
      (expect-crypto-error
       (lambda ()
         (aead-open :aes-128-gcm
                    (%aes-gcm-bytes "00000000000000000000000000000000")
                    #()
                    (make-array 16 :element-type '(unsigned-byte 8)
                                :initial-element 0)
                    #()))
       "open zero IV")
      (format t "cl-crypto-kit: AES-GCM public API boundary tests passed (4 checks)~%")))
  t)
