(in-package #:crypto-kit/test)

(defun %check-ed25519-sign (condition message)
  (unless condition (error "~A" message)))

(defun run-ed25519-sign-tests ()
  (dolist (vector
           '(("9d61b19deffd5a60ba844af492ec2cc44449c5697b326919703bac031cae7f60"
 "" "d75a980182b10ab7d54bfed3c964073a0ee172f3daa62325af021a68f707511a"
 "e5564300c360ac729086e2cc806e828a84877f1eb8e5d974d873e065224901555fb8821590a33bacc61e39701cf9b46bd25bf5f0595bbe24655141438e7a100b")
             ("4ccd089b28ff96da9db6c346ec114e0f5b8a319f35aba624da8cf6ed4fb8a6fb"
              "72" "3d4017c3e843895a92b70aa74d1b7ebc9c982ccf2ec4968cc0cd55f12af4660c"
              "92a009a9f0d4cab8720e820b5f642540a2b27b5416503f8fb3762223ebdb69da085ac1e43e15996e458f3613d0f11d8c387b2eaeb4302aeeb00d291612bb0c00")
             ("c5aa8df43f9f837bedb7442f31dcb7b166d38535076f094b85ce3a2e0b4458f7"
              "af82" "fc51cd8e6218a1a38da47ed00230f0580816ed13ba3303ac5deb911548908025"
              "6291d657deec24024827e69c3abe01a30ce548a284743a445e3680d7db5ac3ac18ff9b538d16f290ae67f760984dc6594a7c15e9716ed28dc027beceea1ec40a")))
    (destructuring-bind (seed-hex message-hex public-hex signature-hex) vector
      (let* ((seed (hex seed-hex))
             (message (hex message-hex))
             (public-key (crypto-kit::ed25519-public-key-from-seed seed))
             (signature (crypto-kit::ed25519-sign seed message)))
        (%check-ed25519-sign (equalp public-key (hex public-hex))
                             "RFC 8032 Ed25519 public key mismatch")
        (%check-ed25519-sign (equalp signature (hex signature-hex))
                             "RFC 8032 Ed25519 signature mismatch")
        (%check-ed25519-sign (ed25519-verify signature message public-key)
                             "RFC 8032 Ed25519 signature did not verify"))))
  (let* ((seed (hex "9d61b19deffd5a60ba844af492ec2cc44449c5697b326919703bac031cae7f60"))
         (message (hex ""))
         (public-key (crypto-kit::ed25519-public-key-from-seed seed))
         (signature (crypto-kit::ed25519-sign seed message)))
    (setf (aref signature 0) (logxor (aref signature 0) 1))
    (%check-ed25519-sign (not (ed25519-verify signature message public-key))
                         "Modified Ed25519 signature was accepted"))
  (let* ((seed (hex "4ccd089b28ff96da9db6c346ec114e0f5b8a319f35aba624da8cf6ed4fb8a6fb"))
         (message (hex "72"))
         (public-key (crypto-kit::ed25519-public-key-from-seed seed))
         (signature (crypto-kit::ed25519-sign seed message)))
    (setf (aref message 0) #x73)
    (%check-ed25519-sign (not (ed25519-verify signature message public-key))
                         "Ed25519 signature verified for a modified message"))
  (format t "RFC 8032 Ed25519 vectors passed~%")
  t)
