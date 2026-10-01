(in-package #:crypto-kit)

(defstruct (ec-curve (:constructor make-ec-curve (prime a b gx gy n size))) prime a b gx gy n size)
(defparameter +p256+
  (make-ec-curve #xffffffff00000001000000000000000000000000ffffffffffffffffffffffff
                 #xffffffff00000001000000000000000000000000fffffffffffffffffffffffc
                 #x5ac635d8aa3a93e7b3ebbd55769886bc651d06b0cc53b0f63bce3c3e27d2604b
                 #x6b17d1f2e12c4247f8bce6e563a440f277037d812deb33a0f4a13945d898c296
                 #x4fe342e2fe1a7f9b8ee7eb4a7c0f9e162bce33576b315ececbb6406837bf51f5
                 #xffffffff00000000ffffffffffffffffbce6faada7179e84f3b9cac2fc632551 32))

(defun ec-mod (x c) (mod x (ec-curve-prime c)))
(defun ec-pow (x e c) (let ((r 1) (b (ec-mod x c))) (loop while (> e 0) do (when (oddp e) (setf r (ec-mod (* r b) c))) (setf b (ec-mod (* b b) c) e (ash e -1))) r))
(defun ec-inv (x c) (if (zerop x) 0 (ec-pow x (- (ec-curve-prime c) 2) c)))
(defun ec-point (x y) (cons x y))
(defun ec-infinity-p (q) (null q))
(defun ec-add (p q c)
  (cond ((null p) q) ((null q) p)
        ((= (car p) (car q))
         (if (= (mod (+ (cdr p) (cdr q)) (ec-curve-prime c)) 0) nil
             (let* ((m (ec-mod (* (+ (* 3 (expt (car p) 2)) (ec-curve-a c))
                                   (ec-inv (* 2 (cdr p)) c)) c))
                    (x (ec-mod (- (expt m 2) (* 2 (car p))) c)))
               (ec-point x (ec-mod (- (* m (- (car p) x)) (cdr p)) c)))))
        (t (let* ((m (ec-mod (* (- (cdr q) (cdr p))
                                (ec-inv (- (car q) (car p)) c)) c))
                   (x (ec-mod (- (expt m 2) (car p) (car q)) c)))
             (ec-point x (ec-mod (- (* m (- (car p) x)) (cdr p)) c))))))

(defun ec-on-curve-p (q c)
  (and q (integerp (car q)) (integerp (cdr q))
       (< (car q) (ec-curve-prime c)) (< (cdr q) (ec-curve-prime c))
       (= (mod (ec-pow (cdr q) 2 c) (ec-curve-prime c))
          (mod (+ (ec-pow (car q) 3 c)
                  (* (ec-curve-a c) (car q)) (ec-curve-b c)) (ec-curve-prime c)))))

(defun ec-mul (k q c &key fixed)
  (let ((r0 nil) (r1 q) (bits (or fixed (integer-length k))))
    (loop for i downfrom (1- bits) to 0 do
      (let ((bit (if (logbitp i k) 1 0)))
        (if (zerop bit)
            (setf r1 (ec-add r0 r1 c) r0 (ec-add r0 r0 c))
            (setf r0 (ec-add r0 r1 c) r1 (ec-add r1 r1 c))))) r0))

(defun ec-octets-int (v) (read-be v 0 (length v)))
(defun ec-int-octets (x n) (put-be x n))
(defun ec-decode-point (octets c)
  (let ((n (ec-curve-size c)))
    (unless (and (= (length octets) (1+ (* 2 n))) (= (aref octets 0) 4))
      (crypto-error "Invalid uncompressed EC point encoding"))
    (let ((q (ec-point (read-be octets 1 n) (read-be octets (1+ n) n))))
      (unless (ec-on-curve-p q c) (crypto-error "EC point is not on curve")) q)))
(defun ec-encode-point (q c)
  (unless (ec-on-curve-p q c) (crypto-error "Cannot encode invalid EC point"))
  (concat-octets #(4) (ec-int-octets (car q) (ec-curve-size c))
                 (ec-int-octets (cdr q) (ec-curve-size c))))

(defun p256-ecdh (private-key public-key)
  (let* ((q (ec-decode-point public-key +p256+))
         (k (if (arrayp private-key) (ec-octets-int private-key) private-key)))
    (unless (and (integerp k) (> k 0) (< k (ec-curve-n +p256+)))
      (crypto-error "Invalid P-256 private scalar"))
    (let ((shared (ec-mul k q +p256+ :fixed 256)))
      (unless shared (crypto-error "Invalid EC shared point"))
      (ec-int-octets (car shared) 32))))
