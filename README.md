# Aegaeon - CriTCL library for using mowgli's event loop and VIO abstraction in Tcl apps

requires tcl 8.6.

## Installation:

    make dl-mowgli
    make cfg-mowgli
    make make-mowgli
    make aegaeon-pkg
    cp -Rp lib/aegaeon /wherever/you/autoload/your/tcl/pkgs/from/aegaeon

## Run a test case:

Assuming you have an ircd on 127.0.0.1, and your system target is freebsd-amd64,

    tclsh8.6 tests/mowglibot-tls.tcl freebsd-amd64

You should get a spew of text that comes from your IRCd.
