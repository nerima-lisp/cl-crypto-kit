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
   (crypto-kit::aead-seal :aes-128-gcm
              (%aes-gcm-bytes "00000000000000000000000000000000")
              (%aes-gcm-bytes "000000000000000000000000")
              (%aes-gcm-bytes "")
              (%aes-gcm-bytes ""))
   (%aes-gcm-bytes "58e2fccefa7e3061367f1d57a4e7455a")
   "NIST GCM empty")
  (let ((sealed
          (crypto-kit::aead-seal :aes-128-gcm
                     (%aes-gcm-bytes "00000000000000000000000000000000")
                     (%aes-gcm-bytes "000000000000000000000000")
                     (%aes-gcm-bytes "00000000000000000000000000000000")
                     (%aes-gcm-bytes ""))))
    (%aes-gcm-check
     sealed
     (%aes-gcm-bytes
      "0388dace60b6a392f328c2b971b2fe78ab6e47d42cec13bdf53a67b21257bddf")
     "NIST GCM AES-128")
    (%aes-gcm-check
     (crypto-kit::aead-open :aes-128-gcm
                (%aes-gcm-bytes "00000000000000000000000000000000")
                (%aes-gcm-bytes "000000000000000000000000")
                sealed
                (%aes-gcm-bytes ""))
     (%aes-gcm-bytes "00000000000000000000000000000000")
     "NIST GCM open")
    (setf (aref sealed 0) (logxor (aref sealed 0) 1))
    (handler-case
        (progn
          (crypto-kit::aead-open :aes-128-gcm
                     (%aes-gcm-bytes "00000000000000000000000000000000")
                     (%aes-gcm-bytes "000000000000000000000000")
                     sealed
                     (%aes-gcm-bytes ""))
          (error "modified ciphertext was accepted"))
      (crypto-kit::aead-authentication-failure () nil)))
  (let ((sealed
          (crypto-kit::aead-seal :aes-256-gcm
                     (%aes-gcm-bytes
                      "0000000000000000000000000000000000000000000000000000000000000000")
                     (%aes-gcm-bytes "000000000000000000000000")
                     (%aes-gcm-bytes "00000000000000000000000000000000")
                     (%aes-gcm-bytes ""))))
    (%aes-gcm-check
     sealed
     (%aes-gcm-bytes
      "cea7403d4d606b6e074ec5d3baf39d18d0d1c8a799996bf0265b98b5d48ab919")
     "NIST GCM AES-256"))
  t)
