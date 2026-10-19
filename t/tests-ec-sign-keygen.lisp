(in-package #:crypto-kit/test)

(defun %ec-sign-hex (text)
  (let ((octets (make-array (/ (length text) 2)
                           :element-type '(unsigned-byte 8))))
    (dotimes (index (length octets) octets)
      (setf (aref octets index)
            (parse-integer text :start (* index 2) :end (+ (* index 2) 2)
                           :radix 16)))))

(defun %ec-sign-ascii (text)
  (map '(vector (unsigned-byte 8)) #'char-code text))

(defun %ec-sign-der-integer (text)
  (let* ((octets (%ec-sign-hex text))
         (encoded (if (logbitp 7 (aref octets 0))
                      (crypto-kit::concat-octets #(0) octets)
                      octets)))
    (concatenate '(vector (unsigned-byte 8))
                 (vector 2 (length encoded)) encoded)))

(defun %ec-sign-expected-der (r s)
  (let* ((r-bytes (%ec-sign-der-integer r))
         (s-bytes (%ec-sign-der-integer s))
         (body (concatenate '(vector (unsigned-byte 8)) r-bytes s-bytes)))
    (concatenate '(vector (unsigned-byte 8))
                 (vector 48 (length body)) body)))

(defun %ec-sign-check-rfc6979-p256 ()
  (let* ((private (%ec-sign-hex
                   "c9afa9d845ba75166b5c215767b1d6934e50c3db36e89b127b8a622b120f6721"))
         (public (crypto-kit::concat-octets
                  #(4)
                  (%ec-sign-hex "60fed4ba255a9d31c961eb74c6356d68c049b8923b61fa6ce669622e60f29fb6")
                  (%ec-sign-hex "7903fe1008b8bc99a41ae9e95628bc64f2f1b20c2d7e9f5177a3c294d4462299")))
         (actual-public
           (crypto-kit::%ec-public-from-scalar crypto-kit::+p256+ private))
         (message (%ec-sign-ascii "sample"))
         (expected (%ec-sign-expected-der
                    "efd48b2aacb6a8fd1140dd9cd45e81d69d2c877b56aaf991c34d0ea84eaf3716"
                    "f7cb1c942d657c41d436c7a1b6e29f65f3e900dbb9aff4064dc4ab2f843acda8"))
         (signature (crypto-kit::ecdsa-sign-p256 message private)))
    (unless (equalp actual-public public)
      (error "P-256 fixed-flow public derivation mismatch"))
    (unless (equalp signature expected)
      (error "P-256 RFC 6979 Appendix A.2.5 signature mismatch"))
    (unless (crypto-kit:ecdsa-verify-p256 message public signature)
      (error "P-256 RFC 6979 Appendix A.2.5 signature did not verify"))
    (unless (equalp signature (crypto-kit::ecdsa-sign-p256 message private))
      (error "P-256 RFC 6979 signing was not deterministic"))))

(defun run-ec-sign-keygen-tests ()
  (let ((zero-scalar (make-array 32 :element-type '(unsigned-byte 8)
                                 :initial-element 0)))
    (handler-case
        (progn
          (make-ec-private-key :p256 zero-scalar)
          (error "P-256 private-key constructor accepted a zero scalar"))
      (crypto-error () t)))
  (%ec-sign-check-rfc6979-p256)
  (format t "P-256 RFC 6979 signing checks passed~%")
  t)
