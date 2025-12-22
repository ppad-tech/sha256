{
  description = "Pure Haskell SHA-256 and HMAC-SHA256";

  inputs = {
    ppad-nixpkgs = {
      type = "git";
      url  = "git://git.ppad.tech/nixpkgs.git";
      ref  = "master";
    };
    ppad-base16 = {
      type = "git";
      url  = "git://git.ppad.tech/base16.git";
      ref  = "master";
      inputs.ppad-nixpkgs.follows = "ppad-nixpkgs";
    };
    flake-utils.follows = "ppad-nixpkgs/flake-utils";
    nixpkgs.follows = "ppad-nixpkgs/nixpkgs";
  };

  outputs = { self, nixpkgs, flake-utils, ppad-nixpkgs
            , ppad-base16 }:
    flake-utils.lib.eachDefaultSystem (system:
      let
        lib = "ppad-sha256";

        pkgs = import nixpkgs { inherit system; };
        hlib = pkgs.haskell.lib;
        llvm = pkgs.llvmPackages_15.llvm;

        base16 = ppad-base16.packages.${system}.default;

        hpkgs = pkgs.haskell.packages.ghc981.extend (new: old: {
          ppad-base16 = base16;
          ${lib} = old.callCabal2nixWithOptions lib ./. "--enable-profiling" {
            ppad-base16 = new.ppad-base16;
          };
        });

        cc    = pkgs.stdenv.cc;
        ghc   = hpkgs.ghc;
        cabal = hpkgs.cabal-install;
      in
        {
          packages.default = hpkgs.${lib};

          devShells.default = hpkgs.shellFor {
            packages = p: [
              (hlib.doBenchmark p.${lib})
            ];

            buildInputs = [
              cabal
              cc
              llvm
            ];

            doBenchmark = true;

            shellHook = ''
              PS1="[${lib}] \w$ "
              echo "entering ${system} shell, using"
              echo "cc:    $(${cc}/bin/cc --version)"
              echo "ghc:   $(${ghc}/bin/ghc --version)"
              echo "cabal: $(${cabal}/bin/cabal --version)"
              echo "llc:   $(${llvm}/bin/llc --version | head -2 | tail -1)"
            '';
          };
        }
      );
}

