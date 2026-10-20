{
  description = "Pure Common Lisp cryptographic primitives.";

  inputs = {
    nixpkgs.url = "github:NixOS/nixpkgs/nixos-unstable";
    cl-weave = {
      url = "github:nerima-lisp/cl-weave/v1.3.0";
      inputs.nixpkgs.follows = "nixpkgs";
    };
  };

  outputs = { self, nixpkgs, cl-weave, ... }:
    let
      systems = [ "aarch64-darwin" "x86_64-linux" ];
      checkSystems = systems ++ [ "aarch64-linux" ];
      asd = builtins.readFile ./cl-crypto-kit.asd;
      version = builtins.elemAt
        (builtins.split "\""
          (builtins.elemAt (builtins.split ":version \"" asd) 2)) 0;
      forEachSystem = function:
        nixpkgs.lib.genAttrs systems (system: function system (import nixpkgs { inherit system; }));
      forEachCheckSystem = function:
        nixpkgs.lib.genAttrs checkSystems (system: function system (import nixpkgs { inherit system; }));
    in {
      formatter = forEachSystem (system: pkgs: pkgs.nixfmt-tree);
      packages = forEachSystem (system: pkgs: {
        default = pkgs.stdenvNoCC.mkDerivation {
          pname = "cl-crypto-kit";
          inherit version;
          src = self;
          dontBuild = true;
          installPhase = ''
            runHook preInstall
            target="$out/share/common-lisp/source/cl-crypto-kit"
            mkdir -p "$target"
            cp -r CHANGELOG.md LICENSE README.md cl-crypto-kit.asd src t "$target"/
            runHook postInstall
          '';
          meta = {
            description = "Pure Common Lisp cryptographic primitives";
            license = pkgs.lib.licenses.mit;
          };
        };
      });
      devShells = forEachSystem (system: pkgs: {
        default = pkgs.mkShell {
          packages = [ cl-weave.packages.${system}.default pkgs.sbcl pkgs.coreutils pkgs.perl ];
        };
      });
      checks = forEachCheckSystem (system: pkgs:
        let
          clWeaveSource = cl-weave.outPath;
          check = pkgs.runCommand "cl-crypto-kit-check" {
            nativeBuildInputs = [ pkgs.sbcl pkgs.openssl ];
          } ''
            cp -r ${self} source
            export XDG_CACHE_HOME="$TMPDIR/cl-crypto-kit-cache"
            export CL_SOURCE_REGISTRY="$PWD/source//:${clWeaveSource}//"
            cd source
            set -o pipefail
            test_log="$TMPDIR/cl-crypto-kit-test.log"
            sbcl --version | tee "$test_log"
            sbcl --noinform --non-interactive \
              --eval '(require :asdf)' \
              --eval '(asdf:test-system "cl-crypto-kit")' 2>&1 | tee -a "$test_log"
            grep -Eq 'cl-crypto-kit: AES-GCM disassembly assertions [1-9][0-9]* passed \((x86-64|arm64)\)' "$test_log"
            grep -Eq 'RFC HMAC [1-9][0-9]*, RFC HKDF [1-9][0-9]* vectors passed' "$test_log"
            grep -Eq 'Wycheproof X25519 [1-9][0-9]*, Ed25519 [1-9][0-9]* vectors passed' "$test_log"
            grep -Eq 'cl-crypto-kit: Signature checks [1-9][0-9]* passed' "$test_log"
            bash scripts/crypto-hash-openssl.sh
            touch "$out"
          '';
        in {
          default = check;
          test = check;
        });
      apps = forEachSystem (system: pkgs:
        let
          clWeave = cl-weave.packages.${system}.default;
          sourceRegistry = "${clWeave}/share/common-lisp/source//";
          test = pkgs.writeShellApplication {
            name = "cl-crypto-kit-test";
            runtimeInputs = [ pkgs.sbcl clWeave ];
            text = ''
              export CL_SOURCE_REGISTRY="$PWD//:${sourceRegistry}"
              sbcl --noinform --non-interactive \
                --eval '(require :asdf)' \
                --eval '(asdf:test-system "cl-crypto-kit")'
            '';
          };
        in {
          default = { type = "app"; program = "${test}/bin/cl-crypto-kit-test"; };
          test = { type = "app"; program = "${test}/bin/cl-crypto-kit-test"; };
        });
    };
}
