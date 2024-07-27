with import <nixpkgs> {};
mkShell {
  packages = with pkgs; [
    nodejs
    go
    gotools
  ];
  shellHook = '''';
  nativeBuildInputs = with pkgs; [];
  buildInputs = with pkgs; [];
#  NIX_LD_LIBRARY_PATH = lib.makeLibraryPath [
#    stdenv.cc.cc
    # ...
#  ];
#  NIX_LD = lib.fileContents "${stdenv.cc}/nix-support/dynamic-linker";
}
