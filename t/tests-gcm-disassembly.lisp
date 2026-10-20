(in-package #:crypto-kit/test)

(defun %gcm-disassembly-split-words (string)
  (let ((words nil)
        (start nil))
    (loop for index from 0 below (length string)
          for character = (char string index)
          do (if (find character '(#\Space #\Tab #\Return #\Newline #\,))
                 (when start
                   (push (subseq string start index) words)
                   (setf start nil))
                 (unless start
                   (setf start index))))
    (when start
      (push (subseq string start) words))
    (nreverse words)))

(defun %gcm-disassembly-label-p (word)
  (and (> (length word) 1)
       (char= (char word 0) #\L)
       (char= (char word (1- (length word))) #\:)))

(defun %gcm-disassembly-label-name-p (word)
  (and (> (length word) 1)
       (char= (char word 0) #\L)
       (every #'digit-char-p (subseq word 1))))

(defun %gcm-disassembly-hex-word-p (word)
  (and word
       (every
        (lambda (character)
          (digit-char-p character 16))
        word)))

(defun %gcm-disassembly-record (line index)
  (when (and (> (length line) 1) (char= (char line 0) #\;))
    (let ((colon (position #\: line)))
      (when
          (and colon
               (%gcm-disassembly-hex-word-p
                (string-trim '(#\Space #\Tab) (subseq line 1 colon))))
        (let* ((words (%gcm-disassembly-split-words (subseq line (1+ colon))))
               (label-word (and words (%gcm-disassembly-label-p (first words))))
               (label
                (and label-word
                     (subseq (first words) 0 (1- (length (first words))))))
               (words
                (if label-word
                    (rest words)
                    words))
               (words
                (if (%gcm-disassembly-hex-word-p (first words))
                    (rest words)
                    words))
               (mnemonic (first words)))
          (when (or label mnemonic)
            (list :index
                  index
                  :label
                  label
                  :mnemonic
                  (and mnemonic (string-upcase mnemonic))
                  :operands
                  (mapcar #'string-upcase (rest words))
                  :line
                  line)))))))

(defun %gcm-disassembly-records (text)
  (with-input-from-string (input text)
    (loop for line = (read-line input nil)
          for index from 0
          while line
          for record = (%gcm-disassembly-record line index)
          when record
            collect record)))

(defun %gcm-disassembly-architecture ()
  (cond
    ((member :x86-64 *features*) :x86-64)
    ((member :arm64 *features*) :arm64)
    (t
     (error "Unsupported SBCL target for AES-GCM disassembly checks: ~S"
            *features*))))

(defun %gcm-disassembly-conditional-branch-p (mnemonic architecture)
  (case architecture
    (:x86-64
     (or (and (>= (length mnemonic) 2)
              (string= mnemonic "J" :end1 1)
              (not (member mnemonic (list "JMP" "JMPQ" "JMPW")
                           :test (function string=))))
         (member mnemonic (list "LOOP" "LOOPE" "LOOPZ" "LOOPNE" "LOOPNZ")
                 :test (function string=))))
    (:arm64
     (member mnemonic
             (list "BEQ" "BNE" "BCS" "BCC" "BHS" "BLO" "BMI" "BPL" "BVS" "BVC"
                   "BHI" "BLS" "BGE" "BLT" "BGT" "BLE" "B.EQ" "B.NE" "B.CS"
                   "B.CC" "B.HS" "B.LO" "B.MI" "B.PL" "B.VS" "B.VC" "B.HI"
                   "B.LS" "B.GE" "B.LT" "B.GT" "B.LE" "CBZ" "CBNZ" "TBZ" "TBNZ")
             :test (function string=)))))

(defun %gcm-disassembly-call-p (record architecture)
  (let ((mnemonic (getf record :mnemonic))
        (operands (getf record :operands)))
    (case architecture
      (:x86-64
       (or (and (>= (length mnemonic) 4) (string= mnemonic "CALL" :end1 4))
           (and (>= (length mnemonic) 3)
                (string= mnemonic "JMP" :end1 3)
                (not (%gcm-disassembly-label-name-p (first operands))))))
      (:arm64
       (or (string= mnemonic "BL")
           (and (>= (length mnemonic) 3) (string= mnemonic "BLR" :end1 3))
           (string= mnemonic "BLX")
           (string= mnemonic "BR")
           (and (string= mnemonic "B")
                (not (%gcm-disassembly-label-name-p (first operands)))))))))

(defun %gcm-disassembly-number (word)
  (let ((number-text (string-left-trim '(#\# #\$) word)))
    (ignore-errors
     (if (and (> (length number-text) 2)
              (string-equal number-text "0x" :end1 2))
         (parse-integer number-text :start 2 :radix 16 :junk-allowed t)
         (parse-integer number-text :junk-allowed t)))))

(defun %gcm-disassembly-normalize-register (word architecture)
  (case architecture
    (:x86-64
     (or (cdr (assoc word
                     (list (cons "EAX" "RAX") (cons "AX" "RAX") (cons "AL" "RAX") (cons "AH" "RAX")
                           (cons "EBX" "RBX") (cons "BX" "RBX") (cons "BL" "RBX") (cons "BH" "RBX")
                           (cons "ECX" "RCX") (cons "CX" "RCX") (cons "CL" "RCX") (cons "CH" "RCX")
                           (cons "EDX" "RDX") (cons "DX" "RDX") (cons "DL" "RDX") (cons "DH" "RDX")
                           (cons "ESI" "RSI") (cons "SI" "RSI") (cons "SIL" "RSI")
                           (cons "EDI" "RDI") (cons "DI" "RDI") (cons "DIL" "RDI")
                           (cons "EBP" "RBP") (cons "BP" "RBP") (cons "BPL" "RBP")
                           (cons "ESP" "RSP") (cons "SP" "RSP") (cons "SPL" "RSP"))
                     :test (function string=)))
         (if (and (>= (length word) 3)
                  (string= word "R" :end1 1)
                  (find (char word (1- (length word))) "DWB"))
             (subseq word 0 (1- (length word)))
             word)))
    (:arm64
     (if (and (> (length word) 1)
              (string= word "W" :end1 1)
              (every (function digit-char-p) (subseq word 1)))
         (concatenate (quote string) "X" (subseq word 1))
         word))
    (otherwise word)))

(defun %gcm-disassembly-zero-initializer-p (record counter architecture)
  (let* ((mnemonic (getf record :mnemonic))
         (operands (getf record :operands))
         (normalized-counter
          (%gcm-disassembly-normalize-register counter architecture)))
    (or
     (and (eq architecture :x86-64)
          (equal mnemonic "XOR")
          (= (length operands) 2)
          (equal normalized-counter
                 (%gcm-disassembly-normalize-register (first operands)
                                                      architecture))
          (equal normalized-counter
                 (%gcm-disassembly-normalize-register (second operands)
                                                      architecture))
          t)
     (and (member mnemonic '("MOV" "MOVZ" "MOVL" "MOVQ") :test #'string=)
          (equal normalized-counter
                 (%gcm-disassembly-normalize-register (first operands)
                                                      architecture))
          (member 0 (mapcar #'%gcm-disassembly-number (rest operands)))))))

(defun %gcm-disassembly-loop-branch-p (mnemonic architecture)
  (case architecture
    (:x86-64 (or (string= mnemonic "JL")
                 (string= mnemonic "JNE")))
    (:arm64 (string= mnemonic "BNE"))))
(defun %gcm-disassembly-register-write-p (record register architecture)
  (let* ((mnemonic (getf record :mnemonic))
         (operands (getf record :operands))
         (normalized-register
          (%gcm-disassembly-normalize-register register architecture))
         (normalized-operands
          (mapcar (lambda (operand)
                    (%gcm-disassembly-normalize-register operand architecture))
                  operands)))
    (cond
      ((eq architecture :x86-64)
       (or (and (member mnemonic (list "XCHG" "XADD" "CMPXCHG")
                        :test (function string=))
                (member normalized-register normalized-operands
                        :test (function string=)))
           (and (equal normalized-register (first normalized-operands))
                (not (member mnemonic
                             (list "CMP" "TEST" "PUSH" "PUSHQ" "CALL" "CALLQ"
                                   "JMP" "JMPQ" "JMPW" "RET" "NOP" "BT"
                                   "LOOP" "LOOPE" "LOOPZ" "LOOPNE" "LOOPNZ")
                             :test (function string=))))))
      ((eq architecture :arm64)
       (and (equal normalized-register (first normalized-operands))
            (not (or (member mnemonic
                             (list "CMP" "CMN" "TST" "TEQ" "RET" "BR" "BLR"
                                   "BL" "CBZ" "CBNZ" "TBZ" "TBNZ"
                                   "STR" "STRB" "STRH" "STP" "STNP" "STUR"
                                   "STURB" "STURH" "STLR" "STLUR")
                             :test (function string=))
                     (and (> (length mnemonic) 1)
                          (string= mnemonic "B" :end1 1)))))))))

(defun %gcm-disassembly-increment-updates-counter-p (records record
                                                             counter
                                                             architecture
                                                             step
                                                             target-index
                                                             branch-index)
  (let* ((index (getf record :index))
         (operands (getf record :operands))
         (destination
          (%gcm-disassembly-normalize-register (first operands) architecture))
         (source
          (%gcm-disassembly-normalize-register (second operands) architecture))
         (normalized-counter
          (%gcm-disassembly-normalize-register counter architecture))
         (counter-update-p
          (case architecture
            (:x86-64 (equal destination normalized-counter))
            (:arm64 (equal source normalized-counter))))
         (next-instruction
          (and (eq architecture :arm64)
               (find-if
                (lambda (next)
                  (and (> (getf next :index) index)
                       (< (getf next :index) branch-index)
                       (getf next :mnemonic)))
                records)))
         (counter-result-p
          (or (equal destination normalized-counter)
              (and next-instruction
                   (equal (getf next-instruction :mnemonic) "MOV")
                   (equal normalized-counter
                          (%gcm-disassembly-normalize-register
                           (first (getf next-instruction :operands))
                           architecture))
                   (equal destination
                          (%gcm-disassembly-normalize-register
                           (second (getf next-instruction :operands))
                           architecture)))))
         (counter-writes
          (remove-if-not
           (lambda (candidate)
             (let ((candidate-index (getf candidate :index)))
               (and (<= target-index candidate-index)
                    (< candidate-index branch-index)
                    (%gcm-disassembly-register-write-p
                     candidate counter architecture))))
           records))
         (counter-writes-p
          (or (and (equal destination normalized-counter)
                   (= (length counter-writes) 1)
                   (= (getf (first counter-writes) :index) index))
              (and next-instruction
                   (not (equal destination normalized-counter))
                   (= (length counter-writes) 1)
                   (= (getf (first counter-writes) :index)
                      (getf next-instruction :index))))))
    (and (< target-index index)
         (< index branch-index)
         (equal (getf record :mnemonic) "ADD")
         (member step (mapcar #'%gcm-disassembly-number operands))
         counter-update-p
         counter-result-p
         counter-writes-p)))

(defun %gcm-disassembly-fixed-loop-p (records architecture bound step)
  (labels ((x86-scaled-counter-source (records branch-index compare-counter)
             (let* ((instructions
                     (remove-if-not
                      (lambda (record)
                        (and (< (getf record :index) branch-index)
                             (getf record :mnemonic)))
                      records))
                    (last-three (last instructions 3))
                    (move (first last-three))
                    (shift (second last-three))
                    (compare (third last-three))
                    (move-operands (and move (getf move :operands)))
                    (shift-operands (and shift (getf shift :operands)))
                    (compare-operands (and compare (getf compare :operands)))
                    (counter-source (second move-operands)))
               (when (and (= (length last-three) 3)
                          (equal (getf move :mnemonic) "MOV")
                          (equal (first move-operands) compare-counter)
                          (equal (getf shift :mnemonic) "SAR")
                          (equal (first shift-operands) compare-counter)
                          (= (or (%gcm-disassembly-number
                                  (second shift-operands))
                                 -1)
                             1)
                          (equal (getf compare :mnemonic) "CMP")
                          (equal (first compare-operands) compare-counter))
                 counter-source))))
    (let ((branches
           (remove-if-not
            (lambda (record)
              (and (getf record :mnemonic)
                   (%gcm-disassembly-conditional-branch-p
                    (getf record :mnemonic)
                    architecture)))
            records)))
      (and (= (length branches) 1)
           (let* ((branch (first branches))
                  (branch-mnemonic (getf branch :mnemonic))
                  (branch-index (getf branch :index))
                  (target (first (getf branch :operands)))
                  (target-record
                   (find target
                         records
                         :key
                         (lambda (record)
                           (getf record :label))
                         :test
                         (function equal)))
                  (target-index (and target-record (getf target-record :index)))
                  (previous-instruction
                   (car
                    (last
                     (remove-if-not
                      (lambda (record)
                        (and (< (getf record :index) branch-index)
                             (getf record :mnemonic)))
                      records))))
                  (compare-operands
                   (and previous-instruction
                        (equal (getf previous-instruction :mnemonic) "CMP")
                        (getf previous-instruction :operands)))
                  (compare-counter (first compare-operands))
                  (compare-bound (second compare-operands))
                  (scaled-counter
                   (and (eq architecture :x86-64)
                        (string= branch-mnemonic "JNE")
                        (x86-scaled-counter-source records
                                                  branch-index
                                                  compare-counter)))
                  (counter (or scaled-counter compare-counter))
                  (fixed-bound
                   (and counter
                        (if scaled-counter
                            (and (evenp bound)
                                 (= (or (%gcm-disassembly-number compare-bound)
                                        -1)
                                    (/ bound 2)))
                            (= (or (%gcm-disassembly-number compare-bound) -1)
                               bound))))
                  (fixed-increment
                   (and counter
                        (some
                         (lambda (record)
                           (and target-index
                                (< target-index (getf record :index))
                                (%gcm-disassembly-increment-updates-counter-p
  records
  record
  counter
  architecture
  step
  target-index
  branch-index)))
                         records)))
                  (zero-initialized
                   (and target-index
                        counter
                        (let ((normalized-counter
                               (%gcm-disassembly-normalize-register
                                counter
                                architecture)))
                          (some
                           (lambda (record)
                             (and (< (getf record :index) target-index)
                                  (%gcm-disassembly-zero-initializer-p
                                   record
                                   counter
                                   architecture)
                                  (not
                                   (some
                                    (lambda (later)
                                      (and
                                       (< (getf record :index)
                                          (getf later :index))
                                       (< (getf later :index) target-index)
                                       (some
                                        (lambda (operand)
                                          (equal normalized-counter
                                                 (%gcm-disassembly-normalize-register
                                                  operand
                                                  architecture)))
                                        (getf later :operands))))
                                    records))))
                           records)))))
             (and target-index
                  (< target-index branch-index)
                  (%gcm-disassembly-loop-branch-p branch-mnemonic architecture)
                  fixed-bound
                  fixed-increment
                  zero-initialized))))))

(defun %gcm-disassembly-allocation-p (text)
  (let ((text (string-upcase text)))
    (some
     (lambda (marker)
       (search marker text))
     '("ALLOC" "TRAMP" "MORECORE" "MAKE-ARRAY"))))

(defun %gcm-disassembly-violations (text architecture bound step)
  (let* ((records (%gcm-disassembly-records text))
         (calls
          (remove-if-not
           (lambda (record)
             (and (getf record :mnemonic)
                  (%gcm-disassembly-call-p record architecture)))
           records)))
    (append
     (when calls
       '(:call))
     (unless (%gcm-disassembly-fixed-loop-p records architecture bound step)
       '(:branch))
     (when (%gcm-disassembly-allocation-p text)
       '(:allocation)))))

(defun %gcm-disassemble (function)
  (with-output-to-string (output)
    (let ((*standard-output* output))
      (disassemble function))))

(defun %gcm-generic-arithmetic-control (left right)
  (+ left right))

(defun %gcm-disassembly-check (condition label &optional disassembly)
  (unless condition
    (if disassembly
        (error "~A~%~A" label disassembly)
        (error "~A" label)))
  t)

(defun run-gcm-disassembly-tests ()
  (let ((checks 0)
        (architecture (%gcm-disassembly-architecture)))
    (labels ((check (condition label &optional disassembly)
               (incf checks)
               (%gcm-disassembly-check condition label disassembly))
             (check-function (function bound)
               (let* ((disassembly (%gcm-disassemble function))
                      (violations
                       (%gcm-disassembly-violations disassembly
                                                    architecture
                                                    bound
                                                    2))
                      (name (symbol-name function)))
                 (check (not (member :call violations))
                        (format nil "~A contains a call or tail-call" name)
                        disassembly)
                 (check (not (member :branch violations))
                        (format nil
                                "~A has a non-fixed conditional branch"
                                name)
                        disassembly)
                 (check (not (member :allocation violations))
                        (format nil "~A contains a heap allocation path" name)
                        disassembly))))
      (check-function 'crypto-kit::%gcm-mul-into 256)
      (check-function 'crypto-kit::%gcm-bytes-to-words 8)
      (progn
        (check-function 'crypto-kit::%gcm-xor-into 32)
        (check-function 'crypto-kit::%gcm-constant-time-equal 32))
      (let* ((disassembly (%gcm-disassemble '%gcm-generic-arithmetic-control))
             (violations
              (%gcm-disassembly-violations disassembly architecture 256 2)))
        (check (member :call violations)
               "Generic arithmetic control did not expose a call or tail-call"
               disassembly)
        (check violations
               "Generic arithmetic control passed the GHASH checker"
               disassembly)))
    (format t
            "cl-crypto-kit: AES-GCM disassembly assertions ~D passed (~A)~%"
            checks
            (if (eq architecture :x86-64)
                "x86-64"
                "arm64"))
    (format t
            "cl-crypto-kit: AES-GCM disassembly positive control rejected generic arithmetic~%")
    (format t
            "cl-crypto-kit: AES-GCM disassembly criteria passed for %gcm-mul-into, %gcm-bytes-to-words, %gcm-xor-into, and %gcm-constant-time-equal: no calls or tail-calls, fixed-count loop branches, no heap allocation~%")
    t))
