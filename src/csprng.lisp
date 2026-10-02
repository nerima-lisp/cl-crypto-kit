(in-package #:crypto-kit)

(define-condition csprng-error (error)
  ((message :initarg :message :reader csprng-error-message))
  (:report (lambda (condition stream)
             (write-string (csprng-error-message condition) stream))))

(export '(csprng-error csprng-error-message))

;; This implementation is scoped to macOS and Linux, where /dev/urandom is
;; provided by the operating system.  The device is opened for each call, so
;; this code retains no descriptor or PRNG state across fork; fork safety of
;; the operating-system source itself remains the platform's responsibility.
(defun random-octets (length)
  (when (or (not (integerp length)) (minusp length))
    (crypto-error "Random length must be a non-negative integer"))
  (let ((result (make-array length :element-type '(unsigned-byte 8))))
    (handler-case
        (with-open-file (stream "/dev/urandom"
                                :direction :input
                                :element-type '(unsigned-byte 8))
          (loop with position = 0
                while (< position length)
                for next-position = (read-sequence result stream
                                                    :start position
                                                    :end length)
                do (if (> next-position position)
                       (setf position next-position)
                       (error 'csprng-error
                              :message "Could not read enough random bytes"))))
      (csprng-error (condition) (error condition))
      (file-error (condition)
        (declare (ignore condition))
        (error 'csprng-error :message "Secure random source is unavailable"))
      (stream-error (condition)
        (declare (ignore condition))
        (error 'csprng-error :message "Secure random source could not be read")))
    result))
