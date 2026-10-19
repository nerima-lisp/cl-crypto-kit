(in-package #:crypto-kit)

(declaim (optimize (speed 3) (safety 1) (debug 0)))

(defconstant +sha512-fixed-mask32+ #xffffffff)
(defconstant +sha512-fixed-mask16+ #xffff)

(eval-when (:compile-toplevel :load-toplevel :execute)
  (unless (>= (integer-length most-positive-fixnum) 41)
    (error "Fixed SHA-512 requires fixnums wide enough for 41-bit intermediates")))

(defun %sha512-add2 (a-low a-high b-low b-high)
  (let ((low (+ a-low b-low)))
    (values (logand low +sha512-fixed-mask32+)
            (logand (+ a-high b-high (ash low -32))
                    +sha512-fixed-mask32+))))

(defun %sha512-lanes (low high)
  (vector (logand low +sha512-fixed-mask16+)
          (logand (ash low -16) +sha512-fixed-mask16+)
          (logand high +sha512-fixed-mask16+)
          (logand (ash high -16) +sha512-fixed-mask16+)))
(defun %sha512-add3 (a-low a-high b-low b-high c-low c-high) (multiple-value-bind (sum-low sum-high) (%sha512-add2 a-low a-high b-low b-high) (%sha512-add2 sum-low sum-high c-low c-high)))
(defun %sha512-add4 (a-low a-high b-low b-high c-low c-high d-low d-high) (multiple-value-bind (sum-low sum-high) (%sha512-add3 a-low a-high b-low b-high c-low c-high) (%sha512-add2 sum-low sum-high d-low d-high)))
(defun %sha512-add5 (a-low a-high b-low b-high c-low c-high d-low d-high e-low e-high) (multiple-value-bind (sum-low sum-high) (%sha512-add4 a-low a-high b-low b-high c-low c-high d-low d-high) (%sha512-add2 sum-low sum-high e-low e-high)))

(defun %sha512-rotr64 (low high count) (let* ((lanes (%sha512-lanes low high)) (whole (floor count 16)) (part (mod count 16))) (labels ((lane (index) (aref lanes (mod index 4))) (rotated-lane (index) (let ((source (+ index whole))) (if (zerop part) (lane source) (logand (logior (ash (lane source) (- part)) (ash (lane (1+ source)) (- 16 part))) +sha512-fixed-mask16+))))) (let ((out0 (rotated-lane 0)) (out1 (rotated-lane 1)) (out2 (rotated-lane 2)) (out3 (rotated-lane 3))) (values (logior out0 (ash out1 16)) (logior out2 (ash out3 16)))))))
(defun %sha512-shr64 (low high count) (let ((lanes (%sha512-lanes low high))) (labels ((lane (index) (aref lanes index)) (shifted-lane (index) (if (= index 3) (ash (lane index) (- count)) (logand (logior (ash (lane index) (- count)) (ash (lane (1+ index)) (- 16 count))) +sha512-fixed-mask16+)))) (let ((out0 (shifted-lane 0)) (out1 (shifted-lane 1)) (out2 (shifted-lane 2)) (out3 (shifted-lane 3))) (values (logior out0 (ash out1 16)) (logior out2 (ash out3 16)))))))
(defun %sha512-read-be32 (octets start) (logior (ash (aref octets start) 24) (ash (aref octets (+ start 1)) 16) (ash (aref octets (+ start 2)) 8) (aref octets (+ start 3))))
(defun %sha512-small-sigma0 (low high) (multiple-value-bind (r1-low r1-high) (%sha512-rotr64 low high 1) (multiple-value-bind (r8-low r8-high) (%sha512-rotr64 low high 8) (multiple-value-bind (s7-low s7-high) (%sha512-shr64 low high 7) (values (logxor r1-low r8-low s7-low) (logxor r1-high r8-high s7-high))))))
(defun %sha512-small-sigma1 (low high) (multiple-value-bind (r19-low r19-high) (%sha512-rotr64 low high 19) (multiple-value-bind (r61-low r61-high) (%sha512-rotr64 low high 61) (multiple-value-bind (s6-low s6-high) (%sha512-shr64 low high 6) (values (logxor r19-low r61-low s6-low) (logxor r19-high r61-high s6-high))))))
(defun %sha512-big-sigma0 (low high) (multiple-value-bind (r28-low r28-high) (%sha512-rotr64 low high 28) (multiple-value-bind (r34-low r34-high) (%sha512-rotr64 low high 34) (multiple-value-bind (r39-low r39-high) (%sha512-rotr64 low high 39) (values (logxor r28-low r34-low r39-low) (logxor r28-high r34-high r39-high))))))
(defun %sha512-big-sigma1 (low high) (multiple-value-bind (r14-low r14-high) (%sha512-rotr64 low high 14) (multiple-value-bind (r18-low r18-high) (%sha512-rotr64 low high 18) (multiple-value-bind (r41-low r41-high) (%sha512-rotr64 low high 41) (values (logxor r14-low r18-low r41-low) (logxor r14-high r18-high r41-high))))))
(defun %sha512-ch (e-low e-high f-low f-high g-low g-high)
  (values (logxor (logand e-low f-low) (logand (lognot e-low) g-low))
          (logxor (logand e-high f-high) (logand (lognot e-high) g-high))))
(defun %sha512-maj (a-low a-high b-low b-high c-low c-high) (values (logxor (logand a-low b-low) (logand a-low c-low) (logand b-low c-low)) (logxor (logand a-high b-high) (logand a-high c-high) (logand b-high c-high))))
(defun %sha512-expand-word-fixed (schedule index) (let* ((x (* (- index 15) 2)) (y (* (- index 2) 2)) (target (* index 2))) (multiple-value-bind (sigma0-low sigma0-high) (%sha512-small-sigma0 (aref schedule x) (aref schedule (1+ x))) (multiple-value-bind (sigma1-low sigma1-high) (%sha512-small-sigma1 (aref schedule y) (aref schedule (1+ y))) (multiple-value-bind (sum-low sum-high) (%sha512-add4 (aref schedule (* (- index 16) 2)) (aref schedule (1+ (* (- index 16) 2))) sigma0-low sigma0-high (aref schedule (* (- index 7) 2)) (aref schedule (1+ (* (- index 7) 2))) sigma1-low sigma1-high) (setf (aref schedule target) sum-low (aref schedule (1+ target)) sum-high))))))
(defun %sha512-round-fixed (work schedule index)
  (let* ((a-low (aref work 0)) (a-high (aref work 1))
         (b-low (aref work 2)) (b-high (aref work 3))
         (c-low (aref work 4)) (c-high (aref work 5))
         (d-low (aref work 6)) (d-high (aref work 7))
         (e-low (aref work 8)) (e-high (aref work 9))
         (f-low (aref work 10)) (f-high (aref work 11))
         (g-low (aref work 12)) (g-high (aref work 13))
         (h-low (aref work 14)) (h-high (aref work 15))
         (constant (aref +sha512-k+ index))
         (k-low (ldb (byte 32 0) constant))
         (k-high (ldb (byte 32 32) constant))
         (word-low (aref schedule (* index 2)))
         (word-high (aref schedule (1+ (* index 2)))))
    (multiple-value-bind (sigma1-low sigma1-high)
        (%sha512-big-sigma1 e-low e-high)
      (multiple-value-bind (sigma0-low sigma0-high)
          (%sha512-big-sigma0 a-low a-high)
        (multiple-value-bind (ch-low ch-high)
            (%sha512-ch e-low e-high f-low f-high g-low g-high)
          (multiple-value-bind (majority-low majority-high)
              (%sha512-maj a-low a-high b-low b-high c-low c-high)
            (multiple-value-bind (t1-low t1-high)
                (%sha512-add5 h-low h-high sigma1-low sigma1-high
                              ch-low ch-high k-low k-high word-low word-high)
              (multiple-value-bind (t2-low t2-high)
                  (%sha512-add2 sigma0-low sigma0-high
                                majority-low majority-high)
                (multiple-value-bind (new-a-low new-a-high)
                    (%sha512-add2 t1-low t1-high t2-low t2-high)
                  (multiple-value-bind (new-e-low new-e-high)
                      (%sha512-add2 d-low d-high t1-low t1-high)
                    (setf (aref work 0) new-a-low
                          (aref work 1) new-a-high
                          (aref work 2) a-low
                          (aref work 3) a-high
                          (aref work 4) b-low
                          (aref work 5) b-high
                          (aref work 6) c-low
                          (aref work 7) c-high
                          (aref work 8) new-e-low
                          (aref work 9) new-e-high
                          (aref work 10) e-low
                          (aref work 11) e-high
                          (aref work 12) f-low
                          (aref work 13) f-high
                          (aref work 14) g-low
                          (aref work 15) g-high)))))))))))
(defun %sha512-compress-fixed (state block)
  (let ((schedule (make-array 160 :element-type '(unsigned-byte 32)
                              :initial-element 0))
        (work (copy-seq state)))
    (declare (type (simple-array (unsigned-byte 32) (*)) schedule work))
    (loop for i below 16
          for start = (* i 8)
          do (setf (aref schedule (* i 2))
                   (%sha512-read-be32 block (+ start 4))
                   (aref schedule (1+ (* i 2)))
                   (%sha512-read-be32 block start)))
    (loop for i from 16 below 80
          do (%sha512-expand-word-fixed schedule i))
    (loop for i below 80
          do (%sha512-round-fixed work schedule i))
    (loop for i below 8
          for index = (* i 2)
          do (multiple-value-bind (low high)
                 (%sha512-add2 (aref state index) (aref state (1+ index))
                               (aref work index) (aref work (1+ index)))
               (setf (aref state index) low
                     (aref state (1+ index)) high)))
    state))
(defun %sha512-put32 (output start value)
  (setf (aref output start) (ldb (byte 8 24) value)
        (aref output (+ start 1)) (ldb (byte 8 16) value)
        (aref output (+ start 2)) (ldb (byte 8 8) value)
        (aref output (+ start 3)) (ldb (byte 8 0) value)))
(defun %sha512-fixed-digest (message)
  (unless (typep message '(array (unsigned-byte 8) (*)))
    (crypto-error "SHA-512 input must be an octet vector"))
  (let* ((message-length (length message))
         (block-count (ceiling (+ message-length 17) 128))
         (padded (make-array (* block-count 128)
                             :element-type '(unsigned-byte 8)
                             :initial-element 0))
         (state (make-array 16 :element-type '(unsigned-byte 32))))
    (replace padded message)
    (setf (aref padded message-length) #x80)
    (let ((bit-length (* message-length 8))
          (length-start (- (length padded) 16)))
      (loop for i below 8
            do (setf (aref padded (+ length-start 8 i))
                     (ldb (byte 8 (* 8 (- 7 i))) bit-length))))
    (let ((initial (initial-state :sha512)))
      (loop for i below 8
            for value = (aref initial i)
            for index = (* i 2)
            do (setf (aref state index) (ldb (byte 32 0) value)
                     (aref state (1+ index)) (ldb (byte 32 32) value))))
    (loop for start from 0 below (length padded) by 128
          for block = (make-array 128 :element-type '(unsigned-byte 8))
          do (replace block padded :start2 start :end2 (+ start 128))
             (%sha512-compress-fixed state block))
    (let ((output (make-array 64 :element-type '(unsigned-byte 8))))
      (loop for start from 0 below 64 by 4
            for index = (* (floor start 8) 2)
            do (%sha512-put32 output start
                              (if (= (mod start 8) 0)
                                  (aref state (1+ index))
                                  (aref state index))))
      output)))
(defun %sha512-fixed (message) (%sha512-fixed-digest message))