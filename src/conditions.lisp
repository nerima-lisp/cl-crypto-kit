(in-package #:crypto-kit)

(define-condition crypto-error (error)
  ((message :initarg :message :reader crypto-error-message))
  (:report (lambda (c s) (write-string (crypto-error-message c) s))))

(defun crypto-error (control &rest args)
  (error 'crypto-error :message (apply #'format nil control args)))
