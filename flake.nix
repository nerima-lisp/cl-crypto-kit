{
  description = "Hash, HMAC, and HKDF primitives for Common Lisp.";

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
      forEachSystem = function:
        nixpkgs.lib.genAttrs systems (system: function system (import nixpkgs { inherit system; }));
    in {
      formatter = forEachSystem (system: pkgs: pkgs.nixfmt-tree);
      packages = forEachSystem (system: pkgs: {
        default = pkgs.stdenvNoCC.mkDerivation {
          pname = "cl-crypto-kit";
          version = "0.1.0";
          src = self;
          dontBuild = true;
          installPhase = ''
            runHook preInstall
            target="$out/share/common-lisp/source/cl-crypto-kit"
            mkdir -p "$target"
            cp -r cl-crypto-kit.asd src t "$target"/
            runHook postInstall
          '';
          meta = {
            description = "Hash, HMAC, and HKDF primitives for Common Lisp";
            license = pkgs.lib.licenses.mit;
          };
        };
      });
      devShells = forEachSystem (system: pkgs: {
        default = pkgs.mkShell {
          packages = [ cl-weave.packages.${system}.default pkgs.sbcl pkgs.coreutils pkgs.perl ];
        };
      });
      checks = forEachSystem (system: pkgs:
        let
          clWeave = cl-weave.packages.${system}.default;
        in {
          test = pkgs.runCommand "cl-crypto-kit-check" {
            nativeBuildInputs = [ pkgs.sbcl clWeave ];
          } ''
            cp -r ${self} source
            export XDG_CACHE_HOME="$TMPDIR/cl-crypto-kit-cache"
            export CL_SOURCE_REGISTRY="$PWD/source//:${clWeave}/share/common-lisp/source//"
            cd source
            sbcl --noinform --non-interactive \
              --eval '(require :asdf)' \
              --eval '(asdf:test-system "cl-crypto-kit")'
            touch "$out"
          '';
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
