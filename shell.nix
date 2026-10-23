{ pkgs ? import <nixpkgs> {} }:
pkgs.mkShell {
  nativeBuildInputs = with pkgs; [ cmake pkg-config ];
  buildInputs = [ pkgs.asio pkgs.openssl ] ++ pkgs.lib.optionals pkgs.stdenv.hostPlatform.isLinux [ pkgs.pcsclite ];
}
