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
  (it "converts octets to lowercase hexadecimal"
    (expect (octets-to-hex #()) :to-equal "")
    (expect (octets-to-hex #(#x00 #xab #xff)) :to-equal "00abff"))
  (it "supports incremental MD5 updates across a block boundary"
    (let ((state (make-digest :md5))
          (message "12345678901234567890123456789012345678901234567890123456789012345678901234567890"))
      (loop for start from 0 below (length message) by 7
            do (digest-update state (ascii message) :start start
                             :end (min (length message) (+ start 7))))
      (expect (digest-final state) :to-equalp (hex "57edf4a22be3c955ac49da2e2107b67a"))))
  (it "returns lowercase hexadecimal digests for standard vectors"
    (let* ((million-a (ascii (make-string 1000000 :initial-element #\a)))
           (vectors
             (list
              (list :md5
                    "d41d8cd98f00b204e9800998ecf8427e"
                    "900150983cd24fb0d6963f7d28e17f72"
                    "7707d6ae4e027c70eea2a935c2296f21")
              (list :sha1
                    "da39a3ee5e6b4b0d3255bfef95601890afd80709"
                    "a9993e364706816aba3e25717850c26c9cd0d89d"
                    "34aa973cd4c4daa4f61eeb2bdbad27316534016f")
              (list :sha256
                    "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855"
                    "ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad"
                    "cdc76e5c9914fb9281a1c7e284d73e67f1809a48a497200e046d39ccc7112cd0")
              (list :sha384
                    "38b060a751ac96384cd9327eb1b1e36a21fdb71114be07434c0cc7bf63f6e1da274edebfe76f65fbd51ad2f14898b95b"
                    "cb00753f45a35e8bb5a03d699ac65007272c32ab0eded1631a8b605a43ff5bed8086072ba1e7cc2358baeca134c825a7"
                    "9d0e1809716474cb086e834e310a4a1ced149e9c00f248527972cec5704c2a5b07b8b3dc38ecc4ebae97ddd87f3d8985")
              (list :sha512
                    "cf83e1357eefb8bdf1542850d66d8007d620e4050b5715dc83f4a921d36ce9ce47d0d13c5d85f2b0ff8318d2877eec2f63b931bd47417a81a538327af927da3e"
                    "ddaf35a193617abacc417349ae20413112e6fa4e89a97ea20a9eeee64b55d39a2192992a274fc1a836ba3c23a3feebbd454d4423643ce80e2a9ac94fa54ca49f"
                    "e718483d0ce769644e2e42c7bc15b4638e1f98b13b2044285632a803afa973ebde0ff244877ea60a4cb0432ce577c31beb009c5c2c49aa2e4eadb217ad8cc09b"))))
      (expect (stringp (digest-hex :sha256 (ascii "abc"))) :to-be t)
      (dolist (vector vectors)
        (let ((algorithm (first vector)))
          (expect (string= (digest-hex algorithm #()) (second vector)) :to-be t)
          (expect (string= (digest-hex algorithm (ascii "abc")) (third vector)) :to-be t)
          (expect (string= (digest-hex algorithm million-a) (fourth vector)) :to-be t))))))

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
