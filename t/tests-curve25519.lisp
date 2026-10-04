(in-package #:crypto-kit/test)

(defun curve25519-hex (string)
  (let ((result (make-array (/ (length string) 2)
                            :element-type '(unsigned-byte 8))))
    (dotimes (i (length result) result)
      (setf (aref result i)
            (parse-integer string :start (* i 2) :end (+ (* i 2) 2)
                           :radix 16)))))

(defun check-curve25519 (condition message)
  (unless condition (error "~A" message)))

(defun run-rfc-curve25519-tests ()
  (let ((random (random-octets 32)))
    (check-curve25519 (= (length random) 32) "CSPRNG returned the wrong length")
    (check-curve25519
     (every (lambda (octet) (typep octet '(unsigned-byte 8))) random)
     "CSPRNG returned a non-octet value"))
  (multiple-value-bind (output all-zero-p)
      (x25519
       (curve25519-hex
        "77076d0a7318a57d3c16c17251b26645df4c2f87ebc0992ab177fba51db92c2a")
       (curve25519-hex
        "0900000000000000000000000000000000000000000000000000000000000000"))
    (check-curve25519
     (equalp output
             (curve25519-hex
              "8520f0098930a754748b7ddcb43ef75a0dbf3a0d26381af4eba4a98eaa9b4e6a"))
     "RFC 7748 X25519 vector failed")
    (check-curve25519 (not all-zero-p) "RFC 7748 vector marked all-zero"))
  (multiple-value-bind (output all-zero-p)
      (x25519-base
       (curve25519-hex
        "77076d0a7318a57d3c16c17251b26645df4c2f87ebc0992ab177fba51db92c2a"))
    (check-curve25519
     (equalp output
             (curve25519-hex
              "8520f0098930a754748b7ddcb43ef75a0dbf3a0d26381af4eba4a98eaa9b4e6a"))
     "X25519 base-point wrapper failed")
    (check-curve25519 (not all-zero-p) "X25519 base-point output marked all-zero"))
  (multiple-value-bind (output all-zero-p)
      (x25519 (make-array 32 :element-type '(unsigned-byte 8))
              (make-array 32 :element-type '(unsigned-byte 8)))
    (check-curve25519 all-zero-p "X25519 all-zero output was not reported")
    (check-curve25519
     (every #'zerop output) "X25519 all-zero input did not produce zero"))
  (let ((message (make-array 0 :element-type '(unsigned-byte 8)))
        (public-key (curve25519-hex
                     "d75a980182b10ab7d54bfed3c964073a0ee172f3daa62325af021a68f707511a"))
        (signature (curve25519-hex
                    "e5564300c360ac729086e2cc806e828a84877f1eb8e5d974d873e065224901555fb8821590a33bacc61e39701cf9b46bd25bf5f0595bbe24655141438e7a100b")))
    (check-curve25519
     (ed25519-verify signature message public-key)
     "RFC 8032 signature vector did not verify")
    (setf (aref signature 0) (logxor (aref signature 0) 1))
    (check-curve25519 (not (ed25519-verify signature message public-key))
                      "Ed25519 modified signature was accepted"))
  (let ((k (curve25519-hex
            "0900000000000000000000000000000000000000000000000000000000000000"))
        (u (curve25519-hex
            "0900000000000000000000000000000000000000000000000000000000000000")))
    (dotimes (iteration 1000)
      (multiple-value-bind (next all-zero-p) (x25519 k u)
        (declare (ignore all-zero-p))
        (rotatef k u)
        (setf k next)))
    (check-curve25519
     (equalp k
             (curve25519-hex
              "684cf59ba83309552800ef566f2f4d3c1c3887c49360e3875f2eb94d99532c51"))
     "RFC 7748 1000-iteration vector failed"))
  (format t "cl-crypto-kit: RFC 7748/8032 curve vectors passed~%")
  t)
