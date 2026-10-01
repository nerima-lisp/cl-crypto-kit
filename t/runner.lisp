(in-package #:crypto-kit/test)
(defun run-tests () (unless (run-all :reporter :spec :pass-with-no-tests nil) (error "cl-crypto-kit tests failed.")) t)
