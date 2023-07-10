#!/usr/bin/env bash

OUTDIR=$(dirname "$0")/../internal/file/testdata/putty
[ -d "$OUTDIR" ] || mkdir -p "$OUTDIR"

rm -f "$OUTDIR"/*.ppk

for keytype in rsa1 dsa rsa ecdsa eddsa ed25519 ed448
do
  puttygen -q -t "$keytype" -C "putty-${keytype}" -o "$OUTDIR/${keytype}.ppk" --new-passphrase /dev/null
done
