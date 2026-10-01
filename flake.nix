{
  description = "Hash, HMAC, and HKDF primitives for Common Lisp.";
  inputs = {
    nixpkgs.url = "github:NixOS/nixpkgs/nixos-unstable";
    cl-weave = { url = "github:nerima-lisp/cl-weave/v1.3.0"; inputs.nixpkgs.follows = "nixpkgs"; };
  };
  outputs = { self, nixpkgs, cl-weave, ... }:
    let systems = [ "aarch64-darwin" "x86_64-linux" ];
        each = f: nixpkgs.lib.genAttrs systems (system: f system (import nixpkgs { inherit system; }));
    in {
      formatter = each (system: pkgs: pkgs.nixfmt-tree);
      packages = each (system: pkgs: {
        default = pkgs.stdenvNoCC.mkDerivation {
          pname = "cl-crypto-kit"; version = "0.1.0"; src = self; dontBuild = true;
          installPhase = ''mkdir -p "$out/share/common-lisp/source/cl-crypto-kit"; cp -r cl-crypto-kit.asd src t "$out/share/common-lisp/source/cl-crypto-kit/"'';
          meta.license = pkgs.lib.licenses.mit;
        };
      });
      devShells = each (system: pkgs: { default = pkgs.mkShell { packages = [ cl-weave.packages.${system}.default pkgs.sbcl pkgs.coreutils ]; }; });
      apps = each (system: pkgs: let weave = cl-weave.packages.${system}.default; test = pkgs.writeShellApplication {
        name = "cl-crypto-kit-test"; runtimeInputs = [ pkgs.sbcl weave ];
        text = ''export CL_SOURCE_REGISTRY="$PWD//:${weave}/share/common-lisp/source//"; sbcl --noinform --non-interactive --eval '(require :asdf)' --eval '(asdf:test-system "cl-crypto-kit")' ''; } in {
          default = { type = "app"; program = "${test}/bin/cl-crypto-kit-test"; };
          test = { type = "app"; program = "${test}/bin/cl-crypto-kit-test"; };
        });
    };
