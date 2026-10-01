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
    (declare (ignore word))
    (let ((k (if (> (length key) block) (digest algorithm key) (copy-seq key))))
      (when (< (length k) block)
        (setf k (concatenate '(vector (unsigned-byte 8)) k
                             (make-array (- block (length k)) :element-type '(unsigned-byte 8)
                                         :initial-element 0))))
      (let ((ipad (make-array block :element-type '(unsigned-byte 8)))
            (opad (make-array block :element-type '(unsigned-byte 8))))
        (loop for i below block do (setf (aref ipad i) (logxor #x36 (aref k i))
                                         (aref opad i) (logxor #x5c (aref k i))))
        (digest algorithm (concat-octets opad (digest algorithm (concat-octets ipad data))))))))

(defun hkdf-extract (algorithm salt ikm)
  (hmac algorithm (if (zerop (length salt))
                      (make-array (digest-length algorithm) :element-type '(unsigned-byte 8)
                                  :initial-element 0) salt) ikm))

(defun hkdf-expand (algorithm prk info length)
  (let ((hash-length (digest-length algorithm)))
    (when (or (< length 0) (> length (* 255 hash-length)))
      (crypto-error "HKDF output length is out of range"))
    (let ((result (make-array length :element-type '(unsigned-byte 8))) (previous #()) (pos 0))
      (loop for counter from 1 while (< pos length) do
        (setf previous (hmac algorithm prk (concat-octets previous info
                                                            (make-array 1 :element-type '(unsigned-byte 8)
                                                                        :initial-element counter))))
        (let ((n (min hash-length (- length pos)))) (replace result previous :start1 pos :end1 (+ pos n))
              (incf pos n))) result)))

(defun random-octets (length)
  (when (minusp length) (crypto-error "Random length must not be negative"))
  (let ((result (make-array length :element-type '(unsigned-byte 8))))
    (handler-case
        (with-open-file (stream "/dev/urandom" :direction :input :element-type '(unsigned-byte 8))
          (let ((read (read-sequence result stream)))
            (unless (= read length) (crypto-error "Could not read enough random bytes"))))
      (file-error (condition) (declare (ignore condition))
        (crypto-error "Secure random source is unavailable"))) result))
