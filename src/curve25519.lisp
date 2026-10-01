(in-package #:crypto-kit)

;;; RFC 7748 X25519.  Field elements use sixteen 16-bit limbs; in
;;; particular, the scalar is never assembled as a Lisp integer.

(eval-when (:compile-toplevel :load-toplevel :execute)
  (export 'x25519))

(defconstant +curve25519-limbs+ 16)
(defconstant +curve25519-radix+ 65536)
(defconstant +curve25519-a24+ 121665)

(declaim (inline %curve25519-limbs %curve25519-normalize
                 %curve25519-add %curve25519-sub %curve25519-mul
                 %curve25519-square %curve25519-cswap))

(defun %curve25519-limbs ()
  (make-array +curve25519-limbs+ :element-type '(unsigned-byte 64)
              :initial-element 0))

(defun %curve25519-normalize (x)
  ;; 2^255 = 19 (mod p).  The repeated pass also handles the carry
  ;; introduced when the top limb is folded back into limb zero.
  (dotimes (pass 3)
    (loop for i below 15
          for carry = (floor (aref x i) +curve25519-radix+)
          do (setf (aref x i) (mod (aref x i) +curve25519-radix+)
                   (aref x (1+ i)) (+ (aref x (1+ i)) carry)))
    (let ((carry (floor (aref x 15) 32768)))
      (setf (aref x 15) (mod (aref x 15) 32768)
            (aref x 0) (+ (aref x 0) (* 19 carry)))))
  x)

(defun %curve25519-add (x y)
  (let ((z (%curve25519-limbs)))
    (dotimes (i +curve25519-limbs+ (%curve25519-normalize z))
      (setf (aref z i) (+ (aref x i) (aref y i))))))

(defun %curve25519-sub (x y)
  (let ((z (%curve25519-limbs)))
    ;; Adding 2p keeps every intermediate non-negative.
    (dotimes (i +curve25519-limbs+ (%curve25519-normalize z))
      (setf (aref z i)
            (+ (aref x i)
               (* 2 (cond ((= i 0) 65517)
                          ((= i 15) 32767)
                          (t 65535)))
               (- (aref y i)))))))

(defun %curve25519-mul (x y)
  (let ((product (make-array 32 :element-type '(unsigned-byte 64)
                       :initial-element 0))
        (z (%curve25519-limbs)))
    (dotimes (i 16)
      (dotimes (j 16)
        (incf (aref product (+ i j)) (* (aref x i) (aref y j)))))
    ;; radix^16 = 2^256 = 38 (mod 2^255-19)
    (loop for i from 31 downto 16
          do (incf (aref product (- i 16)) (* 38 (aref product i))))
    (dotimes (i 16) (setf (aref z i) (aref product i)))
    (%curve25519-normalize z)))

(defun %curve25519-square (x)
  (%curve25519-mul x x))

(defun %curve25519-cswap (x y swap)
  ;; SWAP is restricted to 0 or 1 by the ladder.  The mask is therefore
  ;; either all zeroes or all ones without a data-dependent branch.
  (let ((mask (- swap)))
    (dotimes (i +curve25519-limbs+)
      (let ((delta (logand mask (logxor (aref x i) (aref y i)))))
        (setf (aref x i) (logxor (aref x i) delta)
              (aref y i) (logxor (aref y i) delta)))))
  (values x y))

(defun %curve25519-decode (octets)
  (let ((x (%curve25519-limbs)))
    (dotimes (i 32 x)
      (let ((limb (floor i 2)))
        (incf (aref x limb) (ash (aref octets i) (* 8 (mod i 2))))))))

(defun %curve25519-encode (x)
  (let ((x (copy-seq x))
        (out (make-array 32 :element-type '(unsigned-byte 8))))
    (%curve25519-normalize x)
    ;; Canonicalize by subtracting p, selecting the result arithmetically.
    (let ((candidate (copy-seq x)) (borrow 0))
      (dotimes (i 16)
        (let* ((p (cond ((= i 0) 65517)
                        ((= i 15) 32767)
                        (t 65535)))
               (value (- (aref candidate i) p borrow))
               (next-borrow (logand 1 (floor value +curve25519-radix+)))
               (wrapped (mod value +curve25519-radix+)))
          (setf (aref candidate i) wrapped
                borrow next-borrow)))
      (let ((mask (- (logxor borrow 1))))
        (dotimes (i 16)
          (setf (aref x i)
                (logior (logand mask (aref candidate i))
                        (logand (lognot mask) (aref x i)))))))
    (dotimes (i 32 out)
      (setf (aref out i)
            (ldb (byte 8 (* 8 (mod i 2))) (aref x (floor i 2)))))))

(defun %curve25519-invert (x)
  ;; z^(p-2), with the exponent's 255 bits fixed by the field modulus.
  (let ((result (%curve25519-limbs))
        (base (copy-seq x)))
    (setf (aref result 0) 1)
    (loop for bit from 254 downto 0
          do (setf result (%curve25519-square result))
             ;; p-2 = 2^255 - 21: all bits 254..5 and bits 3, 1, 0 are set.
             (when (or (>= bit 5) (= bit 3) (= bit 1) (= bit 0))
               (setf result (%curve25519-mul result base))))
    result))

(defun %curve25519-all-zero-p (octets)
  (let ((accumulator 0))
    (dotimes (i 32 (= accumulator 0))
      (setf accumulator (logior accumulator (aref octets i))))))

(defun x25519 (scalar u-coordinate)
  "Compute RFC 7748 X25519.

Returns two values: the 32-byte shared secret and ALL-ZERO-P.  The latter
is true for the contributory-infinity result and lets callers reject it."
  (check-type scalar octets)
  (check-type u-coordinate octets)
  (unless (= (length scalar) 32)
    (error "X25519 scalar must contain exactly 32 octets"))
  (unless (= (length u-coordinate) 32)
    (error "X25519 u-coordinate must contain exactly 32 octets"))
  (let ((k (copy-seq scalar))
        (u (copy-seq u-coordinate)))
    ;; RFC 7748 pruning and the X25519 decoding rule.
    (setf (aref k 0) (logand (aref k 0) 248)
          (aref k 31) (logior (logand (aref k 31) 127) 64)
          (aref u 31) (logand (aref u 31) 127))
    (let* ((x1 (%curve25519-decode u))
           (x2 (%curve25519-limbs))
           (z2 (%curve25519-limbs))
           (x3 (copy-seq x1))
           (z3 (%curve25519-limbs))
           (swap 0))
      (setf (aref x2 0) 1
            (aref z3 0) 1)
      (loop for bit from 254 downto 0
            do (let ((kt (logand 1 (ash (aref k (floor bit 8)) (- (mod bit 8))))))
                 (setf swap (logxor swap kt))
                 (%curve25519-cswap x2 x3 swap)
                 (%curve25519-cswap z2 z3 swap)
                 (setf swap kt)
                 (let* ((a (%curve25519-add x2 z2))
                        (aa (%curve25519-square a))
                        (b (%curve25519-sub x2 z2))
                        (bb (%curve25519-square b))
                        (e (%curve25519-sub aa bb))
                        (c (%curve25519-add x3 z3))
                        (d (%curve25519-sub x3 z3))
                        (da (%curve25519-mul d a))
                        (cb (%curve25519-mul c b))
                        (sum (%curve25519-add da cb))
                        (difference (%curve25519-sub da cb)))
                   (setf x3 (%curve25519-square sum)
                         z3 (%curve25519-mul x1 (%curve25519-square difference))
                         x2 (%curve25519-mul aa bb)
                         z2 (%curve25519-mul e
                                             (%curve25519-add aa
                                                              (%curve25519-mul
                                                               (let ((a24 (%curve25519-limbs)))
                                                                 (setf (aref a24 0) +curve25519-a24+)
                                                                 a24)
                                                               e)))))))
      (%curve25519-cswap x2 x3 swap)
      (%curve25519-cswap z2 z3 swap)
      (let ((output (%curve25519-encode
                     (%curve25519-mul x2 (%curve25519-invert z2)))))
        (values output (%curve25519-all-zero-p output))))))
