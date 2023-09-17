#!/usr/bin/env bash

OUTDIR=$(dirname "$0")/../internal/file/testdata/ssh1
[ -d "$OUTDIR" ] || mkdir -p "$OUTDIR"

pwfile="$OUTDIR"/password
echo -n hunter2 > "$pwfile"

rm -f "$OUTDIR"/rsa*

puttygen -q -t rsa1 -C "SSH1 RSA" -o "$OUTDIR/rsa" --new-passphrase /dev/null
puttygen -q "$OUTDIR/rsa" -O text -o "$OUTDIR/rsa.txt"
puttygen -q "$OUTDIR/rsa" -C "SSH1 RSA (encrypted)" -o "$OUTDIR/rsa-encrypted" --old-passphrase /dev/null --new-passphrase "$pwfile"
puttygen -q "$OUTDIR/rsa" -O public -o "$OUTDIR/rsa.pub" --old-passphrase /dev/null --new-passphrase "$pwfile"

rm -f "$pwfile"
