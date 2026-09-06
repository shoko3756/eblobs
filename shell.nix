{ pkgs ? import <nixpkgs> {} }:

pkgs.mkShell {
  name = "emailblob";
  buildInputs = with pkgs; [
    gcc
    cmake
    openssl
  ];
}