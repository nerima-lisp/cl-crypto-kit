(in-package #:crypto-kit/test)

(describe "standard digests"
  (it "matches the RFC 1321 MD5 test vectors"
    (dolist (vector '(("" "d41d8cd98f00b204e9800998ecf8427e")
                      ("a" "0cc175b9c0f1b6a831c399e269772661")
                      ("abc" "900150983cd24fb0d6963f7d28e17f72")
                      ("message digest" "f96b697d7cb7938d525a2f31aaf161d0")
                      ("abcdefghijklmnopqrstuvwxyz" "c3fcd3d76192e4007dfb496cca67e13b")
                      ("ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789"
                       "d174ab98d277d9f5a5611c2c9f419d9f")
                      ("12345678901234567890123456789012345678901234567890123456789012345678901234567890"
                       "57edf4a22be3c955ac49da2e2107b67a")))
      (expect (digest :md5 (ascii (first vector))) :to-equalp (hex (second vector)))))
  (it "matches the empty-message vectors"
    (expect (digest :sha1 #()) :to-equalp (hex "da39a3ee5e6b4b0d3255bfef95601890afd80709"))
    (expect (digest :sha256 #()) :to-equalp (hex "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855"))
    (expect (digest :sha384 #()) :to-equalp (hex "38b060a751ac96384cd9327eb1b1e36a21fdb71114be07434c0cc7bf63f6e1da274edebfe76f65fbd51ad2f14898b95b"))
    (expect (digest :sha512 #()) :to-equalp (hex "cf83e1357eefb8bdf1542850d66d8007d620e4050b5715dc83f4a921d36ce9ce47d0d13c5d85f2b0ff8318d2877eec2f63b931bd47417a81a538327af927da3e")))
  (it "supports incremental updates and independent copies"
    (let ((state (make-digest :sha256)))
      (digest-update state (ascii "ab"))
      (let ((copy (digest-copy state)))
        (digest-update state (ascii "c"))
        (digest-update copy (ascii "d"))
        (expect (digest-final state) :to-equalp (digest :sha256 (ascii "abc")))
        (expect (digest-final copy) :to-equalp (digest :sha256 (ascii "abd"))))))
  (it "supports incremental MD5 updates across a block boundary"
    (let ((state (make-digest :md5))
          (message "12345678901234567890123456789012345678901234567890123456789012345678901234567890"))
      (loop for start from 0 below (length message) by 7
            do (digest-update state (ascii message) :start start
                             :end (min (length message) (+ start 7))))
      (expect (digest-final state) :to-equalp (hex "57edf4a22be3c955ac49da2e2107b67a")))))

(describe "HMAC and HKDF"
  (it "matches RFC 4231 HMAC-SHA-256 case 1"
    (expect (hmac :sha256 (make-array 20 :element-type '(unsigned-byte 8) :initial-element #x0b)
                  (ascii "Hi There"))
            :to-equalp (hex "b0344c61d8db38535ca8afceaf0bf12b881dc200c9833da726e9376c2e32cff7")))
  (it "matches RFC 5869 SHA-256 test case 1"
    (let ((ikm (hex "0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b"))
          (salt (hex "000102030405060708090a0b0c")) (info (hex "f0f1f2f3f4f5f6f7f8f9")))
      (expect (hkdf-expand :sha256 (hkdf-extract :sha256 salt ikm) info 42)
              :to-equalp (hex "3cb25f25faacd57a90434f64d0362f2a2d2d0a90cf1a5a4c5db02d56ecc4c5bf34007208d5b887185865")))))

(describe "constant-time and random helpers"
  (it "compares equal-length and unequal-length vectors"
    (expect (constant-time-equal #(1 2) #(1 2)) :to-be t)
    (expect (constant-time-equal #(1 2) #(1 3)) :to-be nil)
    (expect (constant-time-equal #(1) #(1 0)) :to-be nil))
  (it "returns secure octets of the requested length"
    (expect (length (random-octets 32)) :to-equal 32)))
