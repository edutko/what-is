#!/usr/bin/env bash

OUTDIR=$(dirname "$0")/../internal/file/testdata/putty
[ -d "$OUTDIR" ] || mkdir -p "$OUTDIR"

pwfile="$OUTDIR"/password
echo -n hunter2 > "$pwfile"

rm -f "$OUTDIR"/*.ppk

for keytype in dsa rsa ecdsa eddsa ed25519 ed448
do
  puttygen -q -t "$keytype" -C "putty ${keytype}" -o "$OUTDIR/${keytype}.ppk" --new-passphrase /dev/null
done

keytype=ecdsa
puttygen -q "$OUTDIR/${keytype}.ppk" -C "putty ${keytype} (encrypted)" -o "$OUTDIR/${keytype}-enc-defaults.ppk" --old-passphrase /dev/null --new-passphrase "$pwfile"
puttygen -q "$OUTDIR/${keytype}.ppk" -C "putty ${keytype} (encrypted)" -o "$OUTDIR/${keytype}-enc-argon2d.ppk" --ppk-param kdf=argon2d --old-passphrase /dev/null --new-passphrase "$pwfile"
puttygen -q "$OUTDIR/${keytype}.ppk" -C "putty ${keytype} (encrypted)" -o "$OUTDIR/${keytype}-enc-argon2i.ppk" --ppk-param kdf=argon2i --old-passphrase /dev/null --new-passphrase "$pwfile"

keytype=rsa
puttygen -q "$OUTDIR/${keytype}.ppk" -C "puTTY v2 ${keytype}" --ppk-param version=2 -o "$OUTDIR/${keytype}-v2.ppk" --old-passphrase /dev/null --new-passphrase /dev/null

rm -f "$pwfile"
