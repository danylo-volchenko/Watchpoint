{ pkgs ? import <nixpkgs> {} }:

let
  kernel = pkgs.linuxPackages_latest.kernel;
in
pkgs.mkShell {
  name = "kernel-module-dev-shell";

  buildInputs = [
    pkgs.git
    pkgs.bear
    pkgs.clang-tools
    pkgs.gnumake
    pkgs.bashInteractive
    kernel.dev
  ];

  KERNEL_DIR = "${kernel.dev}/lib/modules/${kernel.modDirVersion}/build";
}

