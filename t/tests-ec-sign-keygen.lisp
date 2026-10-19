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
(defun %check-ec-sign (condition message)
  (incf *signature-test-count*)
  (unless condition
    (error "P-256 signature check failed: ~A" message))
  t)

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
    (%check-ec-sign (equalp actual-public public)
                    "RFC 6979 private-key public derivation")
    (%check-ec-sign (equalp signature expected)
                    "RFC 6979 Appendix A.2.5 sample signature")
    (%check-ec-sign (crypto-kit:ecdsa-verify-p256 message public signature)
                    "RFC 6979 Appendix A.2.5 sample verification")
    (%check-ec-sign
     (equalp signature (crypto-kit::ecdsa-sign-p256 message private))
     "RFC 6979 deterministic signing")))
(defun %ec-sign-check-rfc6979-p256-test ()
  (let* ((private (%ec-sign-hex
                   "c9afa9d845ba75166b5c215767b1d6934e50c3db36e89b127b8a622b120f6721"))
         (public
           (crypto-kit::%ec-public-from-scalar crypto-kit::+p256+ private))
         (message (%ec-sign-ascii "test"))
         (expected (%ec-sign-expected-der
                    "f1abb023518351cd71d881567b1ea663ed3efcf6c5132b354f28d3b0b7d38367"
                    "019f4113742a2b14bd25926b49c649155f267e60d3814b4c0cc84250e46f0083"))
         (signature (crypto-kit::ecdsa-sign-p256 message private)))
    (%check-ec-sign (equalp signature expected)
                    "RFC 6979 Appendix A.2.5 test signature")
    (%check-ec-sign (crypto-kit:ecdsa-verify-p256 message public signature)
                    "RFC 6979 Appendix A.2.5 test verification")
    (%check-ec-sign
     (equalp signature (crypto-kit::ecdsa-sign-p256 message private))
     "RFC 6979 test-message deterministic signing")))
(defun %ec-sign-check-p256-max-scalar ()
  (let* ((private (%ec-sign-hex
                   "ffffffff00000000ffffffffffffffffbce6faada7179e84f3b9cac2fc632550"))
         (public
           (crypto-kit::%ec-public-from-scalar crypto-kit::+p256+ private))
         (message (%ec-sign-ascii "P-256 d=n-1 boundary"))
         (signature (crypto-kit::ecdsa-sign-p256 message private)))
    (%check-ec-sign (make-ec-private-key :p256 private)
                    "private-key constructor rejected d=n-1")
    (%check-ec-sign (crypto-kit:ecdsa-verify-p256 message public signature)
                    "P-256 d=n-1 signature did not verify")
    (%check-ec-sign
     (equalp signature (crypto-kit::ecdsa-sign-p256 message private))
     "P-256 d=n-1 signing was not deterministic")))
(defun %ec-sign-check-rfc6979-retry ()
  (let* ((context (crypto-kit::%ec-order-context crypto-kit::+p256+))
         (limb-count (crypto-kit::ec-mod-context-limb-count context))
         (order (crypto-kit::%ec-limbs-from-public-integer
                 (crypto-kit::ec-curve-n crypto-kit::+p256+)
                 limb-count))
         (one (crypto-kit::%ec-limbs-from-public-integer 1 limb-count))
         (private (make-array 32 :element-type '(unsigned-byte 8)
                              :initial-element 0))
         (hash (make-array 32 :element-type '(unsigned-byte 8)
                           :initial-element 0))
         (invalid-octets
           (crypto-kit::%ec-limbs-to-octets order 32))
         (one-octets
           (crypto-kit::%ec-limbs-to-octets one 32))
         (k1 (make-array 32 :element-type '(unsigned-byte 8)
                         :initial-element #x11))
         (v1 (make-array 32 :element-type '(unsigned-byte 8)
                         :initial-element #x22))
         (k2 (make-array 32 :element-type '(unsigned-byte 8)
                         :initial-element #x33))
         (v2 (make-array 32 :element-type '(unsigned-byte 8)
                         :initial-element #x44))
         (k3 (make-array 32 :element-type '(unsigned-byte 8)
                         :initial-element #x55))
         (v3 (make-array 32 :element-type '(unsigned-byte 8)
                         :initial-element #x66))
         (responses (vector k1 v1 k2 v2 invalid-octets k3 v3 one-octets))
         (calls nil)
         (generator
           (crypto-kit::%rfc6979-p256-k-generator
            private hash
            (lambda (key data)
              (let* ((response (copy-seq (aref responses (length calls))))
                     (call (list (copy-seq key)
                                 (copy-seq data)
                                 (copy-seq response))))
                (setf calls (nconc calls (list call)))
                response))))
         (selected (funcall generator)))
    (%check-ec-sign
     (= (crypto-kit::%ec-limbs-valid-scalar-bit order context) 0)
     "forced RFC 6979 candidate was not invalid")
    (%check-ec-sign (equalp selected one)
                    "RFC 6979 generator did not return the following valid candidate")
    (%check-ec-sign (= (length calls) 8)
                    "RFC 6979 generator did not perform the expected HMAC calls")
    (%check-ec-sign
     (let ((candidate-call (fifth calls))
           (key-update-call (sixth calls))
           (value-update-call (seventh calls))
           (next-candidate-call (eighth calls)))
       (and (equalp (first candidate-call) k2)
            (equalp (second candidate-call) v2)
            (equalp (third candidate-call) invalid-octets)
            (equalp (first key-update-call) k2)
            (equalp (second key-update-call)
                    (crypto-kit::concat-octets invalid-octets #(0)))
            (equalp (third key-update-call) k3)
            (equalp (first value-update-call) k3)
            (equalp (second value-update-call) invalid-octets)
            (equalp (third value-update-call) v3)
            (equalp (first next-candidate-call) k3)
            (equalp (second next-candidate-call) v3)
            (equalp (third next-candidate-call) one-octets)))
     "RFC 6979 rejection did not update K and V before the next candidate")))
#+sb-thread
(defun %ec-sign-check-concurrent-field-context-init ()
  (let* ((base crypto-kit::+p256+)
         (curve
           (crypto-kit::make-ec-curve
            (crypto-kit::ec-curve-prime base)
            (crypto-kit::ec-curve-a base)
            (crypto-kit::ec-curve-b base)
            (crypto-kit::ec-curve-gx base)
            (crypto-kit::ec-curve-gy base)
            (crypto-kit::ec-curve-n base)
            (crypto-kit::ec-curve-size base)))
         (thread-count 16)
         (gate (sb-thread:make-semaphore :count 0))
         (threads
           (loop repeat thread-count
                 collect
                 (sb-thread:make-thread
                  (lambda ()
                    (sb-thread:wait-on-semaphore gate)
                    (handler-case
                        (list :ok
                              (crypto-kit::%ec-field-context curve)
                              (crypto-kit::%ec-field-b curve))
                      (error (condition)
                        (list :error condition)))))))
         (results nil))
    (loop repeat thread-count do (sb-thread:signal-semaphore gate))
    (setf results (mapcar #'sb-thread:join-thread threads))
    (%check-ec-sign (= (length results) thread-count)
                    "concurrent field initialization lost a worker")
    (%check-ec-sign
     (every (lambda (result)
              (and (consp result)
                   (eq (first result) :ok)
                   (crypto-kit::ec-mod-context-p (second result))
                   (vectorp (third result))
                   (= (length (third result))
                      (crypto-kit::ec-mod-context-limb-count
                       (second result)))))
            results)
     "concurrent field initialization exposed partial state")
    (%check-ec-sign
     (let ((expected-b (third (first results)))
           (expected-prime (crypto-kit::ec-curve-prime base)))
       (every (lambda (result)
                (and (= (crypto-kit::ec-mod-context-modulus
                         (second result))
                        expected-prime)
                     (equalp (third result) expected-b)))
              results))
     "concurrent field initialization produced inconsistent values")))

(defun run-ec-sign-keygen-tests ()
  (let* ((zero-scalar (make-array 32 :element-type '(unsigned-byte 8)
                                  :initial-element 0))
         (zero-rejected
           (handler-case
               (progn
                 (make-ec-private-key :p256 zero-scalar)
                 nil)
             (crypto-error () t))))
    (%check-ec-sign zero-rejected
                    "private-key constructor accepted a zero scalar"))
  (%ec-sign-check-rfc6979-p256)
  (%ec-sign-check-rfc6979-p256-test)
  (%ec-sign-check-p256-max-scalar)
  (%ec-sign-check-rfc6979-retry)
  #+sb-thread
  (%ec-sign-check-concurrent-field-context-init)
  (format t "P-256 RFC 6979 signing checks passed~%")
  t)
