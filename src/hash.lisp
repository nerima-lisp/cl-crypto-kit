(in-package #:crypto-kit)

(deftype octets () '(simple-array (unsigned-byte 8) (*)))
(defconstant +u32+ #xffffffff)
(defconstant +u64+ #xffffffffffffffff)

(declaim (optimize (speed 3) (safety 1) (debug 0)))
(declaim (inline mask-word rotr rotl32 read-be put-be))

(defun mask-word (value bits) (ldb (byte bits 0) value))
(defun rotr (value count bits)
  (let ((value (mask-word value bits)))
    (mask-word (logior (ash value (- count))
                       (ash (ldb (byte count 0) value) (- bits count))) bits)))
(defun rotl32 (value count)
  (let ((value (mask-word value 32)))
    (mask-word (logior (ash value count) (ash value (- count 32))) 32)))
(defmacro addmod (bits &rest values)
  `(mask-word (+ ,@values) ,bits))
(defun read-be (octets start size)
  (let ((value 0))
    (loop for i below size
          do (setf value (logior (ash value 8) (aref octets (+ start i)))))
    value))
(defun put-be (value size)
  (let ((out (make-array size :element-type '(unsigned-byte 8))))
    (loop for i below size
          do (setf (aref out i) (ldb (byte 8 (* 8 (- size i 1))) value)))
    out))
(defun concat-octets (&rest vectors)
  (let ((out (make-array (reduce #'+ vectors :key #'length)
                         :element-type '(unsigned-byte 8)))
        (position 0))
    (dolist (vector vectors out)
      (replace out vector :start1 position)
      (incf position (length vector)))))

(defparameter +sha1-k+ #( #x5a827999 #x6ed9eba1 #x8f1bbcdc #xca62c1d6))
(defparameter +sha256-k+
  #( #x428a2f98 #x71374491 #xb5c0fbcf #xe9b5dba5 #x3956c25b #x59f111f1
     #x923f82a4 #xab1c5ed5 #xd807aa98 #x12835b01 #x243185be #x550c7dc3
     #x72be5d74 #x80deb1fe #x9bdc06a7 #xc19bf174 #xe49b69c1 #xefbe4786
     #x0fc19dc6 #x240ca1cc #x2de92c6f #x4a7484aa #x5cb0a9dc #x76f988da
     #x983e5152 #xa831c66d #xb00327c8 #xbf597fc7 #xc6e00bf3 #xd5a79147
     #x06ca6351 #x14292967 #x27b70a85 #x2e1b2138 #x4d2c6dfc #x53380d13
     #x650a7354 #x766a0abb #x81c2c92e #x92722c85 #xa2bfe8a1 #xa81a664b
     #xc24b8b70 #xc76c51a3 #xd192e819 #xd6990624 #xf40e3585 #x106aa070
     #x19a4c116 #x1e376c08 #x2748774c #x34b0bcb5 #x391c0cb3 #x4ed8aa4a
     #x5b9cca4f #x682e6ff3 #x748f82ee #x78a5636f #x84c87814 #x8cc70208
     #x90befffa #xa4506ceb #xbef9a3f7 #xc67178f2))
(defparameter +sha512-k+
  #( #x428a2f98d728ae22 #x7137449123ef65cd #xb5c0fbcfec4d3b2f #xe9b5dba58189dbbc
     #x3956c25bf348b538 #x59f111f1b605d019 #x923f82a4af194f9b #xab1c5ed5da6d8118
     #xd807aa98a3030242 #x12835b0145706fbe #x243185be4ee4b28c #x550c7dc3d5ffb4e2
     #x72be5d74f27b896f #x80deb1fe3b1696b1 #x9bdc06a725c71235 #xc19bf174cf692694
     #xe49b69c19ef14ad2 #xefbe4786384f25e3 #x0fc19dc68b8cd5b5 #x240ca1cc77ac9c65
     #x2de92c6f592b0275 #x4a7484aa6ea6e483 #x5cb0a9dcbd41fbd4 #x76f988da831153b5
     #x983e5152ee66dfab #xa831c66d2db43210 #xb00327c898fb213f #xbf597fc7beef0ee4
     #xc6e00bf33da88fc2 #xd5a79147930aa725 #x06ca6351e003826f #x142929670a0e6e70
     #x27b70a8546d22ffc #x2e1b21385c26c926 #x4d2c6dfc5ac42aed #x53380d139d95b3df
     #x650a73548baf63de #x766a0abb3c77b2a8 #x81c2c92e47edaee6 #x92722c851482353b
     #xa2bfe8a14cf10364 #xa81a664bbc423001 #xc24b8b70d0f89791 #xc76c51a30654be30
     #xd192e819d6ef5218 #xd69906245565a910 #xf40e35855771202a #x106aa07032bbd1b8
     #x19a4c116b8d2d0c8 #x1e376c085141ab53 #x2748774cdf8eeb99 #x34b0bcb5e19b48a8
     #x391c0cb3c5c95a63 #x4ed8aa4ae3418acb #x5b9cca4f7763e373 #x682e6ff3d6b2b8a3
     #x748f82ee5defb2fc #x78a5636f43172f60 #x84c87814a1f0ab72 #x8cc702081a6439ec
     #x90befffa23631e28 #xa4506cebde82bde9 #xbef9a3f7b2c67915 #xc67178f2e372532b
     #xca273eceea26619c #xd186b8c721c0c207 #xeada7dd6cde0eb1e #xf57d4f7fee6ed178
     #x06f067aa72176fba #x0a637dc5a2c898a6 #x113f9804bef90dae #x1b710b35131c471b
     #x28db77f523047d84 #x32caab7b40c72493 #x3c9ebe0a15c9bebc #x431d67c49c100d4c
     #x4cc5d4becb3e42b6 #x597f299cfc657e2a #x5fcb6fab3ad6faec #x6c44198c4a475817))

(defparameter +md5-k+
  #( #xd76aa478 #xe8c7b756 #x242070db #xc1bdceee #xf57c0faf #x4787c62a
     #xa8304613 #xfd469501 #x698098d8 #x8b44f7af #xffff5bb1 #x895cd7be
     #x6b901122 #xfd987193 #xa679438e #x49b40821 #xf61e2562 #xc040b340
     #x265e5a51 #xe9b6c7aa #xd62f105d #x02441453 #xd8a1e681 #xe7d3fbc8
     #x21e1cde6 #xc33707d6 #xf4d50d87 #x455a14ed #xa9e3e905 #xfcefa3f8
     #x676f02d9 #x8d2a4c8a #xfffa3942 #x8771f681 #x6d9d6122 #xfde5380c
     #xa4beea44 #x4bdecfa9 #xf6bb4b60 #xbebfbc70 #x289b7ec6 #xeaa127fa
     #xd4ef3085 #x04881d05 #xd9d4d039 #xe6db99e5 #x1fa27cf8 #xc4ac5665
     #xf4292244 #x432aff97 #xab9423a7 #xfc93a039 #x655b59c3 #x8f0ccc92
     #xffeff47d #x85845dd1 #x6fa87e4f #xfe2ce6e0 #xa3014314 #x4e0811a1
     #xf7537e82 #xbd3af235 #x2ad7d2bb #xeb86d391))

(defparameter +md5-shifts+
  #(7 12 17 22  7 12 17 22  7 12 17 22  7 12 17 22
    5  9 14 20  5  9 14 20  5  9 14 20  5  9 14 20
    4 11 16 23  4 11 16 23  4 11 16 23  4 11 16 23
    6 10 15 21  6 10 15 21  6 10 15 21  6 10 15 21))

(defstruct (digest-state (:constructor %make-state)) algorithm h buffer length)
(defun digest-params (algorithm)
  (case algorithm
    (:md5 (values 32 16 64)) (:sha1 (values 32 20 64))
    (:sha256 (values 32 32 64))
    (:sha384 (values 64 48 128)) (:sha512 (values 64 64 128))
    (otherwise (crypto-error "Unknown digest algorithm ~S" algorithm))))
(defun digest-length (algorithm) (nth-value 1 (digest-params algorithm)))
(defun initial-state (algorithm)
  (case algorithm
    (:md5 (copy-seq #( #x67452301 #xefcdab89 #x98badcfe #x10325476)))
    (:sha1 (copy-seq #( #x67452301 #xefcdab89 #x98badcfe #x10325476 #xc3d2e1f0)))
    (:sha256 (copy-seq #( #x6a09e667 #xbb67ae85 #x3c6ef372 #xa54ff53a #x510e527f
                          #x9b05688c #x1f83d9ab #x5be0cd19)))
    (:sha384 (copy-seq #( #xcbbb9d5dc1059ed8 #x629a292a367cd507 #x9159015a3070dd17
                          #x152fecd8f70e5939 #x67332667ffc00b31 #x8eb44a8768581511
                          #xdb0c2e0d64f98fa7 #x47b5481dbefa4fa4)))
    (:sha512 (copy-seq #( #x6a09e667f3bcc908 #xbb67ae8584caa73b #x3c6ef372fe94f82b
                          #xa54ff53a5f1d36f1 #x510e527fade682d1 #x9b05688c2b3e6c1f
                          #x1f83d9abfb41bd6b #x5be0cd19137e2179)))))
(defun make-digest (algorithm)
  (digest-params algorithm)
  (%make-state :algorithm algorithm :h (initial-state algorithm)
               :buffer (make-array 0 :element-type '(unsigned-byte 8)) :length 0))

(defun sha1-compress (h block)
  (let ((w (make-array 80 :initial-element 0)) (a (aref h 0)) (b (aref h 1))
        (c (aref h 2)) (d (aref h 3)) (e (aref h 4)))
    (loop for i below 16 do (setf (aref w i) (read-be block (* i 4) 4)))
    (loop for i from 16 below 80
          do (setf (aref w i) (rotl32 (logxor (aref w (- i 3)) (aref w (- i 8))
                                              (aref w (- i 14)) (aref w (- i 16))) 1)))
    (loop for i below 80
          do (let* ((f (cond ((< i 20) (logior (logand b c) (logand (lognot b) d)))
                             ((< i 40) (logxor b c d))
                             ((< i 60) (logior (logand b c) (logand b d) (logand c d)))
                             (t (logxor b c d))))
                    (k (aref +sha1-k+ (floor i 20)))
                    (t1 (addmod 32 (rotl32 a 5) f e k (aref w i))))
               (psetf e d d c c (rotl32 b 30) b a a t1)))
    (loop for i below 5 for value in (list a b c d e)
          do (setf (aref h i) (addmod 32 (aref h i) value))) h))

(defun md5-compress (h block)
  (let ((m (make-array 16))
        (a (aref h 0)) (b (aref h 1)) (c (aref h 2)) (d (aref h 3)))
    (loop for i below 16
          do (setf (aref m i)
                   (logior (aref block (* i 4))
                           (ash (aref block (+ (* i 4) 1)) 8)
                           (ash (aref block (+ (* i 4) 2)) 16)
                           (ash (aref block (+ (* i 4) 3)) 24))))
    (loop for i below 64
          do (let* ((f (cond ((< i 16) (logior (logand b c) (logand (lognot b) d)))
                             ((< i 32) (logior (logand d b) (logand (lognot d) c)))
                             ((< i 48) (logxor b c d))
                             (t (logxor c (logior b (lognot d))))))
                    (g (cond ((< i 16) i)
                             ((< i 32) (mod (+ (* 5 i) 1) 16))
                             ((< i 48) (mod (+ (* 3 i) 5) 16))
                             (t (mod (* 7 i) 16))))
                    (next (addmod 32 a f (aref m g) (aref +md5-k+ i))))
               (setf a d d c c b b (addmod 32 b (rotl32 next (aref +md5-shifts+ i))))))
    (setf (aref h 0) (addmod 32 (aref h 0) a)
          (aref h 1) (addmod 32 (aref h 1) b)
          (aref h 2) (addmod 32 (aref h 2) c)
          (aref h 3) (addmod 32 (aref h 3) d)) h))

(defun sha256-compress (h block)
  (let ((w (make-array 64 :element-type '(unsigned-byte 32) :initial-element 0))
        (v (make-array 8 :element-type '(unsigned-byte 32))))
    (declare (type (simple-array (unsigned-byte 32) (*)) w v)
             (dynamic-extent w v))
    (replace v h)
    (loop for i below 16 do (setf (aref w i) (read-be block (* i 4) 4)))
    (loop for i from 16 below 64
          do (let ((x (aref w (- i 15))) (y (aref w (- i 2))))
               (setf (aref w i)
                     (addmod 32
                             (logxor (rotr x 7 32) (rotr x 18 32) (ash x -3))
                             (aref w (- i 16))
                             (logxor (rotr y 17 32) (rotr y 19 32) (ash y -10))
                             (aref w (- i 7))))))
    (loop for i below 64
          do (let* ((a (aref v 0)) (b (aref v 1)) (c (aref v 2)) (d (aref v 3))
                    (e (aref v 4)) (f (aref v 5)) (g (aref v 6)) (hh (aref v 7))
                    (s1 (logxor (rotr e 6 32) (rotr e 11 32) (rotr e 25 32)))
                    (ch (logxor (logand e f) (logand (lognot e) g)))
                    (t1 (addmod 32 hh s1 ch (aref +sha256-k+ i) (aref w i)))
                    (s0 (logxor (rotr a 2 32) (rotr a 13 32) (rotr a 22 32)))
                    (maj (logxor (logand a b) (logand a c) (logand b c)))
                    (t2 (addmod 32 s0 maj)))
               (let ((new-a (addmod 32 t1 t2))
                     (new-e (addmod 32 d t1)))
                 (setf (aref v 0) new-a (aref v 1) a (aref v 2) b (aref v 3) c
                       (aref v 4) new-e (aref v 5) e (aref v 6) f (aref v 7) g))))
    (loop for i below 8 for value across v
          do (setf (aref h i) (addmod 32 (aref h i) value))
          finally (return h))))

(defun sha512-compress (h block)
  (let ((w (make-array 80 :element-type '(unsigned-byte 64) :initial-element 0))
        (v (make-array 8 :element-type '(unsigned-byte 64))))
    (declare (type (simple-array (unsigned-byte 64) (*)) w v)
             (dynamic-extent w v))
    (replace v h)
    (loop for i below 16 do (setf (aref w i) (read-be block (* i 8) 8)))
    (loop for i from 16 below 80
          do (let ((x (aref w (- i 15))) (y (aref w (- i 2))))
               (setf (aref w i)
                     (addmod 64
                             (logxor (rotr x 1 64) (rotr x 8 64) (ash x -7))
                             (aref w (- i 16))
                             (logxor (rotr y 19 64) (rotr y 61 64) (ash y -6))
                             (aref w (- i 7))))))
    (loop for i below 80
          do (let* ((a (aref v 0)) (b (aref v 1)) (c (aref v 2)) (d (aref v 3))
                    (e (aref v 4)) (f (aref v 5)) (g (aref v 6)) (hh (aref v 7))
                    (s1 (logxor (rotr e 14 64) (rotr e 18 64) (rotr e 41 64)))
                    (ch (logxor (logand e f) (logand (lognot e) g)))
                    (t1 (addmod 64 hh s1 ch (aref +sha512-k+ i) (aref w i)))
                    (s0 (logxor (rotr a 28 64) (rotr a 34 64) (rotr a 39 64)))
                    (maj (logxor (logand a b) (logand a c) (logand b c)))
                    (t2 (addmod 64 s0 maj)))
               (let ((new-a (addmod 64 t1 t2))
                     (new-e (addmod 64 d t1)))
                 (setf (aref v 0) new-a (aref v 1) a (aref v 2) b (aref v 3) c
                       (aref v 4) new-e (aref v 5) e (aref v 6) f (aref v 7) g))))
    (loop for i below 8 for value across v
          do (setf (aref h i) (addmod 64 (aref h i) value))
          finally (return h))))

(defun compress (state block)
  (case (digest-state-algorithm state)
    (:md5 (md5-compress (digest-state-h state) block))
    (:sha1 (sha1-compress (digest-state-h state) block))
    (:sha256 (sha256-compress (digest-state-h state) block))
    ((:sha384 :sha512) (sha512-compress (digest-state-h state) block))))
(defun digest-update (state input &key (start 0) end)
  (let* ((end (or end (length input))) (old (digest-state-buffer state))
         (all (make-array (+ (length old) (- end start)) :element-type '(unsigned-byte 8))))
    (replace all old) (replace all input :start1 (length old) :start2 start :end2 end)
    (loop with block-size = (nth-value 2 (digest-params (digest-state-algorithm state)))
          with block = (make-array block-size :element-type '(unsigned-byte 8))
          for position from 0 by block-size
          while (<= (+ position block-size) (length all))
          do (replace block all :start2 position :end2 (+ position block-size))
             (compress state block)
          finally (setf (digest-state-buffer state) (subseq all position)))
    (incf (digest-state-length state) (- end start)) state))
(defun digest-copy (state)
  (let ((copy (copy-digest-state state)))
    (setf (digest-state-h copy) (copy-seq (digest-state-h state))
          (digest-state-buffer copy) (copy-seq (digest-state-buffer state))) copy))
(defun digest-final (state)
  (let* ((copy (digest-copy state))
         (word-bits (nth-value 0 (digest-params (digest-state-algorithm copy))))
         (output-bytes (nth-value 1 (digest-params (digest-state-algorithm copy))))
         (block-size (nth-value 2 (digest-params (digest-state-algorithm copy))))
         (length-bytes (if (= word-bits 64) 16 8))
         (message-length (digest-state-length copy))
         (padding-length (+ 1 (mod (- block-size 1 (length (digest-state-buffer copy))
                                      length-bytes) block-size) length-bytes))
         (padding (make-array padding-length :element-type '(unsigned-byte 8)
                              :initial-element 0)))
    (setf (aref padding 0) #x80)
    (let* ((message-bits (* message-length 8))
           (low (logand message-bits +u64+))
           (high (if (= length-bytes 16)
                     (logand (floor message-bits (ash 1 64)) +u64+) 0)))
      (if (eq (digest-state-algorithm copy) :md5)
          (replace padding
                   (make-array 8 :element-type '(unsigned-byte 8)
                               :initial-contents
                               (loop for i below 8 collect (ldb (byte 8 (* i 8)) low)))
                   :start1 (- padding-length 8))
          (progn
            (replace padding (put-be high 8) :start1 (- padding-length length-bytes))
            (replace padding (put-be low 8) :start1 (- padding-length 8))))
    (digest-update copy padding)
    (apply #'concat-octets
           (loop for value across (digest-state-h copy)
                 for i below (/ output-bytes (/ word-bits 8))
                 collect (if (eq (digest-state-algorithm copy) :md5)
                             (make-array 4 :element-type '(unsigned-byte 8)
                                         :initial-contents
                                         (list (ldb (byte 8 0) value)
                                               (ldb (byte 8 8) value)
                                               (ldb (byte 8 16) value)
                                               (ldb (byte 8 24) value)))
                             (put-be value (/ word-bits 8))))))))
(defun digest (algorithm octets)
  (digest-final (digest-update (make-digest algorithm) octets)))
