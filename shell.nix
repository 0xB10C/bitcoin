{ pkgs ? import <nixpkgs> {}, unstable-pkgs ? import <nixos-unstable/nixpkgs> {}}:
pkgs.mkShell {

    nativeBuildInputs = [
	    pkgs.autoconf
	    pkgs.automake
	    pkgs.libtool
	    pkgs.pkg-config
	    pkgs.boost
	    pkgs.libevent
	    pkgs.zeromq
	    pkgs.sqlite
      pkgs.libsystemtap
    ];

    # needed in 'autogen.sh'
    LIBTOOLIZE = "libtoolize";

    # needed for 'configure' to find boost
    # Run ./configure with the argument '--with-boost-libdir=\$NIX_BOOST_LIB_DIR'"
    NIX_BOOST_LIB_DIR = "${pkgs.boost}/lib";

    shellHook = ''
	    echo "Bitcoin Core build shell"
    '';
}
