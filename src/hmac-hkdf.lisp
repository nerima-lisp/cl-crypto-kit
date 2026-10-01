(in-package #:crypto-kit)

(defun constant-time-equal (a b)
  (let ((different (logxor (length a) (length b))))
    (loop for i below (max (length a) (length b))
          do (setf different (logior different
                                     (if (and (< i (length a)) (< i (length b)))
                                         (logxor (aref a i) (aref b i)) 0))))
    (zerop different)))

(defun hmac (algorithm key data)
  (multiple-value-bind (word output block) (digest-params algorithm)
    (declare (ignore word output))
    ;; RFC 2104 hashes keys longer than the hash block size, then zero-pads
    ;; every shorter key to exactly one block.
    (let* ((key-block (if (> (length key) block)
                          (digest algorithm key)
                          (copy-seq key)))
           (normalized-key (make-array block :element-type '(unsigned-byte 8)
                                       :initial-element 0))
           (ipad (make-array block :element-type '(unsigned-byte 8)))
           (opad (make-array block :element-type '(unsigned-byte 8))))
      (replace normalized-key key-block :end2 (min block (length key-block)))
      (loop for i below block do
        (setf (aref ipad i) (logxor #x36 (aref normalized-key i))
              (aref opad i) (logxor #x5c (aref normalized-key i))))
      (digest algorithm
              (concat-octets opad
                             (digest algorithm (concat-octets ipad data)))))))

(defun hkdf-extract (algorithm salt ikm)
  (hmac algorithm (if (zerop (length salt))
                      (make-array (digest-length algorithm) :element-type '(unsigned-byte 8)
                                  :initial-element 0) salt) ikm))

(defun hkdf-expand (algorithm prk info length)
  (let ((hash-length (digest-length algorithm)))
    (when (or (not (integerp length))
              (minusp length)
              (> length (* 255 hash-length)))
      (crypto-error "HKDF output length is out of range"))
    (let ((result (make-array length :element-type '(unsigned-byte 8))) (previous #()) (pos 0))
      (loop for counter from 1 while (< pos length) do
        (setf previous (hmac algorithm prk (concat-octets previous info
                                                            (make-array 1 :element-type '(unsigned-byte 8)
                                                                        :initial-element counter))))
        (let ((n (min hash-length (- length pos)))) (replace result previous :start1 pos :end1 (+ pos n))
              (incf pos n))) result)))
