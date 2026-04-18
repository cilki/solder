{ pkgs ? import (fetchTarball
  "https://github.com/NixOS/nixpkgs/archive/nixos-unstable.tar.gz") { } }:

with pkgs;

mkShell rec {
  nativeBuildInputs = [ cargo rustc rust-analyzer rustfmt clippy binutils gdb ];
  buildInputs = [ ];
  LD_LIBRARY_PATH = lib.makeLibraryPath buildInputs;
}

