{ pkgs ? import <nixpkgs> {} }:
pkgs.mkShell {
  nativeBuildInputs = with pkgs; [ cmake pkg-config ];
  buildInputs = [ pkgs.asio ] ++ pkgs.lib.optionals pkgs.stdenv.isLinux [ pkgs.pcsclite ];
}
