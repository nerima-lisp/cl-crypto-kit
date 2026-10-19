(in-package #:crypto-kit)

(export 'ed25519-verify)

;;;; RFC 8032 Ed25519.  Points are represented in extended homogeneous
;;;; coordinates (X:Y:T:Z), with all coordinates reduced modulo p.

(defconstant +ed25519-p+ (- (expt 2 255) 19))

(eval-when (:compile-toplevel :load-toplevel :execute)
  (defun modular-expt (base exponent)
    (let ((result 1) (base (mod base +ed25519-p+)))
      (loop while (> exponent 0)
            do (when (oddp exponent)
                 (setf result (mod (* result base) +ed25519-p+)))
               (setf base (mod (* base base) +ed25519-p+))
               (setf exponent (ash exponent -1)))
      result)))

(defconstant +ed25519-l+
  (+ (expt 2 252) 27742317777372353535851937790883648493))
(defconstant +ed25519-d+
  (mod (* -121665 (modular-expt 121666 (- +ed25519-p+ 2))) +ed25519-p+))
(defconstant +ed25519-i+
  (modular-expt 2 (/ (1- +ed25519-p+) 4)))
(defconstant +ed25519-two-d+ (* 2 +ed25519-d+))
(defconstant +ed25519-base-x+
  15112221349535400772501151409588531511454012693041857206046113283949847762202)
(defconstant +ed25519-base-y+
  46316835694926478169428394003475163141307993866256225615783033603165251855960)

(defun ed25519-le-int (octets)
  (loop for i below (length octets)
        sum (ash (aref octets i) (* 8 i))))

(defun ed25519-int-le (value size)
  (let ((result (make-array size :element-type '(unsigned-byte 8))))
    (dotimes (i size result)
      (setf (aref result i) (ldb (byte 8 (* 8 i)) value)))))

(defun ed25519-point (x y z tp)
  (vector (mod x +ed25519-p+) (mod y +ed25519-p+)
          (mod z +ed25519-p+) (mod tp +ed25519-p+)))

(defun ed25519-identity () (ed25519-point 0 1 1 0))
(defun ed25519-base ()
  (ed25519-point +ed25519-base-x+ +ed25519-base-y+ 1
                 (* +ed25519-base-x+ +ed25519-base-y+)))

(defun ed25519-point-add (p q)
  (let* ((x1 (aref p 0)) (y1 (aref p 1)) (t1 (aref p 3)) (z1 (aref p 2))
         (x2 (aref q 0)) (y2 (aref q 1)) (t2 (aref q 3)) (z2 (aref q 2))
         (a (mod (* (- y1 x1) (- y2 x2)) +ed25519-p+))
         (b (mod (* (+ y1 x1) (+ y2 x2)) +ed25519-p+))
         (c (mod (* +ed25519-two-d+ t1 t2) +ed25519-p+))
         (d (mod (* 2 z1 z2) +ed25519-p+))
         (e (mod (- b a) +ed25519-p+))
         (f (mod (- d c) +ed25519-p+))
         (g (mod (+ d c) +ed25519-p+))
         (h (mod (+ b a) +ed25519-p+)))
    (ed25519-point (* e f) (* g h) (* f g) (* e h))))

(defun ed25519-point-double (p) (ed25519-point-add p p))

;;; The selection mask is zero or all ones.  This keeps scalar-bit selection
;;; free of a branch; the loop itself always processes the same 256 bits.
(defun ed25519-select (left right bit)
  (let ((mask (- (logand bit 1))))
    (ed25519-point
     (logior (logand mask (aref left 0)) (logand (lognot mask) (aref right 0)))
     (logior (logand mask (aref left 1)) (logand (lognot mask) (aref right 1)))
     (logior (logand mask (aref left 2)) (logand (lognot mask) (aref right 2)))
     (logior (logand mask (aref left 3)) (logand (lognot mask) (aref right 3))))))

(defun ed25519-scalarmult (point scalar)
  (let ((r0 (ed25519-identity)) (r1 point))
    (loop for i from 255 downto 0
          for bit = (ldb (byte 1 i) scalar)
          do (let* ((swap (ed25519-select r0 r1 bit))
                    (keep (ed25519-select r1 r0 bit))
                    (double (ed25519-point-double keep))
                    (sum (ed25519-point-add keep swap)))
               (setf r0 (ed25519-select sum double bit)
                     r1 (ed25519-select double sum bit))))
    r0))

(defun ed25519-inv (value)
  (modular-expt value (- +ed25519-p+ 2)))

(defun ed25519-point-equal (p q)
  (and (= (mod (- (* (aref p 0) (aref q 2))
                   (* (aref q 0) (aref p 2))) +ed25519-p+) 0)
       (= (mod (- (* (aref p 1) (aref q 2))
                   (* (aref q 1) (aref p 2))) +ed25519-p+) 0)))

(defun ed25519-encode (point)
  (let* ((z-inv (ed25519-inv (aref point 2)))
         (x (mod (* (aref point 0) z-inv) +ed25519-p+))
         (y (mod (* (aref point 1) z-inv) +ed25519-p+))
         (result (ed25519-int-le y 32)))
    (setf (aref result 31) (logior (aref result 31) (ash (logand x 1) 7)))
    result))

(defun ed25519-decode (encoding)
  (unless (and (= (length encoding) 32)
               (every (lambda (x) (typep x '(unsigned-byte 8))) encoding))
    (return-from ed25519-decode nil))
  (let* ((sign (ldb (byte 1 7) (aref encoding 31)))
         (y (ed25519-le-int encoding))
         (y (logand y (1- (ash 1 255)))))
    ;; RFC 8032 requires the field element encoding to be canonical.
    (when (>= y +ed25519-p+) (return-from ed25519-decode nil))
    (let* ((yy (mod (* y y) +ed25519-p+))
           (xx (mod (* (- yy 1)
                       (ed25519-inv (mod (+ (* +ed25519-d+ yy) 1)
                                           +ed25519-p+)))
                     +ed25519-p+))
           (x (modular-expt xx (/ (+ 3 +ed25519-p+) 8))))
      (unless (= (mod (* x x) +ed25519-p+) xx)
        (setf x (mod (* x +ed25519-i+) +ed25519-p+)))
      (unless (= (mod (* x x) +ed25519-p+) xx)
        (return-from ed25519-decode nil))
      (when (and (= x 0) (= sign 1)) (return-from ed25519-decode nil))
      (when (/= (logand x 1) sign)
        (setf x (- +ed25519-p+ x)))
      (ed25519-point x y 1 (mod (* x y) +ed25519-p+)))))

(defun ed25519-small-order-p (point)
  (ed25519-point-equal (ed25519-scalarmult point 8) (ed25519-identity)))

(defun ed25519-hash-int (&rest octets)
  (ed25519-le-int (digest :sha512 (apply #'concat-octets octets))))

(defun ed25519-verify (signature message public-key)
  (unless (and (= (length signature) 64) (= (length public-key) 32))
    (return-from ed25519-verify nil))
  (let* ((r-encoding (subseq signature 0 32))
         (s-encoding (subseq signature 32 64))
         (s (ed25519-le-int s-encoding))
         (a (ed25519-decode public-key))
         (r (ed25519-decode r-encoding)))
    (when (or (null a) (null r) (>= s +ed25519-l+)
              (ed25519-small-order-p a) (ed25519-small-order-p r))
      (return-from ed25519-verify nil))
    (let* ((k (mod (ed25519-hash-int r-encoding public-key message)
                   +ed25519-l+))
           (left (ed25519-scalarmult (ed25519-base) s))
           (right (ed25519-point-add r (ed25519-scalarmult a k))))
      ;; Multiplication by 8 makes the check robust against all cofactor
      ;; torsion and is the RFC 8032-compatible strict verification equation.
      (ed25519-point-equal (ed25519-scalarmult left 8)
                           (ed25519-scalarmult right 8)))))

(defvar *ed25519-field-context* nil)
(defvar *ed25519-order-context* nil)

(defun %ed25519-field-context ()
  (or *ed25519-field-context*
      (setf *ed25519-field-context*
            (%ec-montgomery-context +ed25519-p+ 32))))

(defun %ed25519-order-context ()
  (or *ed25519-order-context*
      (setf *ed25519-order-context*
            (%ec-montgomery-context +ed25519-l+ 32))))

(defun %ed25519-limbs-from-little-endian (octets limb-count)
  (let ((limbs (make-array limb-count :initial-element 0)))
    (loop for bit-index below (* 8 (length octets)) do
      (let* ((byte-index (floor bit-index 8))
             (byte-bit (mod bit-index 8))
             (limb-index (floor bit-index +ec-limb-bits+))
             (limb-bit (mod bit-index +ec-limb-bits+))
             (bit (ldb (byte 1 byte-bit) (aref octets byte-index))))
        (setf (aref limbs limb-index)
              (logior (aref limbs limb-index)
                      (ash bit limb-bit)))))
    limbs))

(defun %ed25519-limbs-to-little-endian (limbs size)
  (let ((octets (make-array size :element-type '(unsigned-byte 8)
                            :initial-element 0)))
    (loop for bit-index below (* 8 size) do
      (let* ((limb-index (floor bit-index +ec-limb-bits+))
             (limb-bit (mod bit-index +ec-limb-bits+))
             (octet-index (floor bit-index 8))
             (octet-bit (mod bit-index 8))
             (bit (ldb (byte 1 limb-bit) (aref limbs limb-index))))
        (setf (aref octets octet-index)
              (logior (aref octets octet-index)
                      (ash bit octet-bit)))))
    octets))

(defun %ed25519-scalar-reduce-octets (octets)
  (let* ((context (%ed25519-order-context))
         (limb-count (ec-mod-context-limb-count context))
         (modulus (ec-mod-context-modulus-limbs context))
         (zero (make-array limb-count :initial-element 0))
         (one (make-array limb-count :initial-element 0))
         (remainder zero))
    (setf (aref one 0) 1)
    (loop for bit-index downfrom (1- (* 8 (length octets))) to 0
          for byte-index = (floor bit-index 8)
          for byte-bit = (mod bit-index 8)
          for input-bit = (ldb (byte 1 byte-bit)
                               (aref octets byte-index))
          do (multiple-value-bind (doubled double-carry)
                 (%ec-limbs-add-raw remainder remainder)
               (declare (ignore double-carry))
               (let ((increment (%ec-limbs-select zero one input-bit)))
                 (multiple-value-bind (candidate add-carry)
                     (%ec-limbs-add-raw doubled increment)
                   (declare (ignore add-carry))
                   (multiple-value-bind (difference borrow)
                       (%ec-limbs-sub-raw candidate modulus)
                     (setf remainder
                           (%ec-limbs-select difference candidate borrow)))))))
    remainder))

(defun %ed25519-field-from-public-integer (value context)
  (%ec-to-montgomery
   (%ec-limbs-from-public-integer
    value (ec-mod-context-limb-count context))
   context))

(defun %ed25519-secret-base (context)
  (let* ((x (%ed25519-field-from-public-integer +ed25519-base-x+ context))
         (y (%ed25519-field-from-public-integer +ed25519-base-y+ context))
         (one (ec-mod-context-montgomery-one context)))
    (vector x y one (%ec-montgomery-multiply x y context))))

(defun %ed25519-secret-identity (context)
  (let ((zero (make-array (ec-mod-context-limb-count context)
                          :initial-element 0))
        (one (ec-mod-context-montgomery-one context)))
    (vector zero one one zero)))

(defun %ed25519-secret-point-select (left right bit)
  (vector (%ec-limbs-select (aref right 0) (aref left 0) bit)
          (%ec-limbs-select (aref right 1) (aref left 1) bit)
          (%ec-limbs-select (aref right 2) (aref left 2) bit)
          (%ec-limbs-select (aref right 3) (aref left 3) bit)))

(defun %ed25519-secret-point-add (left right context two-d)
  (let* ((x1 (aref left 0))
         (y1 (aref left 1))
         (z1 (aref left 2))
         (t1 (aref left 3))
         (x2 (aref right 0))
         (y2 (aref right 1))
         (z2 (aref right 2))
         (t2 (aref right 3))
         (a (%ec-montgomery-multiply
             (%ec-modular-subtract y1 x1 context)
             (%ec-modular-subtract y2 x2 context) context))
         (b (%ec-montgomery-multiply
             (%ec-modular-add y1 x1 context)
             (%ec-modular-add y2 x2 context) context))
         (c (%ec-montgomery-multiply
             (%ec-montgomery-multiply two-d t1 context) t2 context))
         (z-product (%ec-montgomery-multiply z1 z2 context))
         (d (%ec-modular-add z-product z-product context))
         (e (%ec-modular-subtract b a context))
         (f (%ec-modular-subtract d c context))
         (g (%ec-modular-add d c context))
         (h (%ec-modular-add b a context)))
    (vector (%ec-montgomery-multiply e f context)
            (%ec-montgomery-multiply g h context)
            (%ec-montgomery-multiply f g context)
            (%ec-montgomery-multiply e h context))))

(defun %ed25519-secret-scalarmult (point scalar context two-d)
  (let ((r0 (%ed25519-secret-identity context))
        (r1 point))
    (loop for bit-index from 255 downto 0
          for bit = (%ec-limbs-bit scalar bit-index)
          do (let* ((swap (%ed25519-secret-point-select r0 r1 bit))
                    (keep (%ed25519-secret-point-select r1 r0 bit))
                    (doubled (%ed25519-secret-point-add keep keep context two-d))
                    (sum (%ed25519-secret-point-add keep swap context two-d)))
               (setf r0 (%ed25519-secret-point-select sum doubled bit)
                     r1 (%ed25519-secret-point-select doubled sum bit))))
    r0))

(defun %ed25519-field-inverse (value context)
  (let ((exponent (%ec-limbs-from-public-integer
                   (- +ed25519-p+ 2)
                   (ec-mod-context-limb-count context))))
    (%ec-montgomery-power value exponent context 255)))

(defun %ed25519-secret-encode (point context)
  (let* ((z-inverse (%ed25519-field-inverse (aref point 2) context))
         (x (%ec-montgomery-multiply (aref point 0) z-inverse context))
         (y (%ec-montgomery-multiply (aref point 1) z-inverse context))
         (normal-x (%ec-from-montgomery x context))
         (normal-y (%ec-from-montgomery y context))
         (encoding (%ed25519-limbs-to-little-endian normal-y 32)))
    (setf (aref encoding 31)
          (logior (aref encoding 31)
                  (ash (%ec-limbs-bit normal-x 0) 7)))
    encoding))

(defun %ed25519-secret-hash-scalar (&rest octets)
  (%ed25519-scalar-reduce-octets
   (%sha512-fixed (apply #'concat-octets octets))))

(defun %ed25519-secret-scalar-mul-add (r challenge scalar)
  (let* ((context (%ed25519-order-context))
         (r-mont (%ec-to-montgomery r context))
         (challenge-mont (%ec-to-montgomery challenge context))
         (scalar-mont (%ec-to-montgomery scalar context))
         (product (%ec-montgomery-multiply challenge-mont scalar-mont context))
         (sum (%ec-modular-add product r-mont context)))
    (%ec-from-montgomery sum context)))

(defun ed25519-seed-material (seed)
  (unless (and (vectorp seed)
               (typep seed '(array (unsigned-byte 8) (*)))
               (= (length seed) 32))
    (crypto-error "Ed25519 seed must be a 32-octet vector"))
  (let ((expanded (%sha512-fixed seed)))
    (setf (aref expanded 0) (logand (aref expanded 0) #xf8)
          (aref expanded 31)
          (logior (logand (aref expanded 31) #x3f) #x40))
    (values expanded
            (%ed25519-limbs-from-little-endian
             (subseq expanded 0 32)
             (ec-mod-context-limb-count (%ed25519-order-context))))))

(defun ed25519-public-key-from-seed (seed)
  (multiple-value-bind (expanded scalar) (ed25519-seed-material seed)
    (declare (ignore expanded))
    (let* ((context (%ed25519-field-context))
           (two-d (%ed25519-field-from-public-integer
                   +ed25519-two-d+ context))
           (point (%ed25519-secret-scalarmult
                   (%ed25519-secret-base context) scalar context two-d)))
      (%ed25519-secret-encode point context))))

(defun ed25519-sign (seed message &optional cached-public-key)
  (unless (typep message '(vector (unsigned-byte 8)))
    (crypto-error "Ed25519 message must be an octet vector"))
  (multiple-value-bind (expanded scalar) (ed25519-seed-material seed)
    (let* ((prefix (subseq expanded 32 64))
           (field-context (%ed25519-field-context))
           (two-d (%ed25519-field-from-public-integer
                   +ed25519-two-d+ field-context))
           (base (%ed25519-secret-base field-context))
           (public-key
             (or cached-public-key
                 (%ed25519-secret-encode
                  (%ed25519-secret-scalarmult
                   base scalar field-context two-d)
                  field-context)))
           (r (%ed25519-secret-hash-scalar prefix message))
           (r-encoding
             (%ed25519-secret-encode
              (%ed25519-secret-scalarmult
               base r field-context two-d)
              field-context))
           (challenge
             (%ed25519-secret-hash-scalar
              r-encoding public-key message))
           (s (%ed25519-secret-scalar-mul-add r challenge scalar)))
      (concat-octets r-encoding
                     (%ed25519-limbs-to-little-endian s 32)))))
