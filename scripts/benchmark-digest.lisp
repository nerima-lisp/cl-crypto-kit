(defpackage #:crypto-kit
            (:use #:cl)
            (:export #:digest
                     #:digest-hex
                     #:octets-to-hex
                     #:make-digest
                     #:digest-update
                     #:digest-copy
                     #:digest-final
                     #:digest-length
                     #:hmac
                     #:hkdf-extract
                     #:hkdf-expand
                     #:rsa-verify-pkcs1-v1_5
                     #:rsa-verify-pss
                     #:verify-rsa-pkcs1-v1_5
                     #:verify-rsa-pss
                     #:constant-time-equal
                     #:random-octets
                     #:aes-encrypt-block
                     #:aes-128
                     #:aes-192
                     #:aes-256
                     #:chacha20-block
                     #:chacha20-keystream
                     #:aead-seal
                     #:aead-open
                     #:p256-ecdh
                     #:p384-point-on-curve-p
                     #:ecdsa-verify
                     #:ecdsa-verify-p256
                     #:ecdsa-verify-p384
                     #:p256-generate-keypair
                     #:verify-signature
                     #:make-rsa-public-key
                     #:make-ec-public-key
                     #:make-ed25519-public-key
                     #:aead-authentication-failure
                     #:crypto-error
                     #:crypto-error-message
                     #:csprng-error
                     #:csprng-error-message
                     #:x25519
                     #:x25519-base
                     #:ed25519-verify))

(eval-when (:compile-toplevel :load-toplevel :execute)
  (require :asdf)
  (require :sb-md5))

(defpackage #:aitools.kernel.domain (:use #:cl))

(defun benchmark-input (size)
  (let ((octets (make-array size :element-type '(unsigned-byte 8)))
        (state #x6d2b79f5))
    (declare (type (simple-array (unsigned-byte 8) (*)) octets)
             (type (unsigned-byte 32) state))
    (loop for index of-type fixnum from 0 below size
          do (setf state (logand #xffffffff (logxor state (ash state 13)))
                   state (logand #xffffffff (logxor state (ash state -17)))
                   state (logand #xffffffff (logxor state (ash state 5)))
                   (aref octets index) (ldb (byte 8 24) state)))
    octets))

(defun benchmark-sample (function input)
  (sb-ext:gc :full t)
  (let ((start (get-internal-real-time)))
    (let ((result (funcall function input)))
      (values result
              (/ (* (- (get-internal-real-time) start) 1000.0d0)
                 internal-time-units-per-second)))))

(defun benchmark-median (values)
  (let* ((sorted (sort (copy-list values) #'<))
         (middle (floor (length sorted) 2)))
    (if (oddp (length sorted))
        (nth middle sorted)
        (/ (+ (nth (1- middle) sorted) (nth middle sorted)) 2.0d0))))

(defun benchmark-absolute-difference (left right)
  (abs (- left right)))

(defun benchmark-arguments ()
  (let ((arguments (uiop:command-line-arguments)))
    (unless (= (length arguments) 1)
      (error
       "Usage: sbcl --script scripts/benchmark-digest.lisp AITOOLS-DIGEST-LISP"))
    arguments))

(defun benchmark-function (package-name function-name)
  (let* ((symbol (find-symbol (string-upcase function-name) package-name))
         (function (and symbol (fboundp symbol) (symbol-function symbol))))
    (unless function
      (error "Could not find ~A::~A" package-name function-name))
    function))

(defun benchmark-one-algorithm (name reference kit input)
  (let ((reference-result (funcall reference input))
        (kit-result (funcall kit input)))
    (unless (string= reference-result kit-result)
      (error "Digest mismatch for ~A" name)))
  (dotimes (warmup 2)
    (declare (ignore warmup))
    (benchmark-sample reference input)
    (benchmark-sample kit input))
  (let ((a-a-deltas nil)
        (reference-times nil)
        (kit-times nil)
        (kit-wins 0))
    (dotimes (pair 2)
      (declare (ignore pair))
      (multiple-value-bind (first-result first-time)
          (benchmark-sample reference input)
        (multiple-value-bind (second-result second-time)
            (benchmark-sample reference input)
          (unless (string= first-result second-result)
            (error "Reference A/A digest mismatch for ~A" name))
          (push (benchmark-absolute-difference first-time second-time)
                a-a-deltas)
          (format t
                  "~A reference/reference ~,1F ms ~,1F ms delta ~,1F ms~%"
                  name
                  first-time
                  second-time
                  (benchmark-absolute-difference first-time second-time)))))
    (dotimes (pair 7)
      (let ((reference-first (evenp pair)))
        (multiple-value-bind (first-result first-time)
            (benchmark-sample
             (if reference-first
                 reference
                 kit)
             input)
          (multiple-value-bind (second-result second-time)
              (benchmark-sample
               (if reference-first
                   kit
                   reference)
               input)
            (unless (string= first-result second-result)
              (error "A/B digest mismatch for ~A" name))
            (let ((reference-time
                   (if reference-first
                       first-time
                       second-time))
                  (kit-time
                   (if reference-first
                       second-time
                       first-time)))
              (push reference-time reference-times)
              (push kit-time kit-times)
              (when (< kit-time reference-time)
                (incf kit-wins))
              (format t
                      "~A pair ~D ~A ~,1F ms ~A ~,1F ms~%"
                      name
                      (1+ pair)
                      (if reference-first
                          "reference"
                          "kit")
                      first-time
                      (if reference-first
                          "kit"
                          "reference")
                      second-time))))))
    (format t
            "~A median: reference ~,1F ms, kit ~,1F ms; kit wins ~D/7; reference A/A median absolute delta ~,1F ms~%"
            name
            (benchmark-median reference-times)
            (benchmark-median kit-times)
            kit-wins
            (benchmark-median a-a-deltas))))

(defun main ()
  (let* ((source (first (benchmark-arguments)))
         (root (uiop:getcwd)))
    (asdf:load-asd (merge-pathnames "cl-crypto-kit.asd" root))
    (asdf:load-system "cl-crypto-kit")
    (load source)
    (let ((input (benchmark-input (* 16 1024 1024))))
      (dolist
          (algorithm
           '(("MD5" "md5-hex" :md5) ("SHA-1" "sha1-hex" :sha1)
             ("SHA-256" "sha256-hex" :sha256)))
        (let ((reference
               (benchmark-function "AITOOLS.KERNEL.DOMAIN" (second algorithm)))
              (kit
               (let ((name (third algorithm)))
                 (lambda (octets)
                   (crypto-kit:digest-hex name octets)))))
          (benchmark-one-algorithm (first algorithm) reference kit input))))))

(main)
