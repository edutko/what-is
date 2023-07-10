#!/usr/bin/env bash

OUTDIR=$(dirname "$0")/../internal/file/testdata/ssh
[ -d "$OUTDIR" ] || mkdir -p "$OUTDIR"

rm -f "$OUTDIR"/id_*

keytype="dsa"
bits="1024"
ssh-keygen -q -N "" -t "$keytype" -b "$bits" -C "${keytype}-${bits}" -f "$OUTDIR/id_${keytype}_${bits}"

keytype="rsa"
for bits in 1024 2048 3072 4096
do
  ssh-keygen -q -N "" -t "$keytype" -b "$bits" -C "${keytype}-${bits}" -f "$OUTDIR/id_${keytype}_${bits}"
done

keytype="ecdsa"
for bits in 256 384 521
do
  ssh-keygen -q -N "" -t "$keytype" -b "$bits" -C "${keytype}-${bits}" -f "$OUTDIR/id_${keytype}_${bits}"
done

keytype="ed25519"
ssh-keygen -q -N "" -t "$keytype" -C "${keytype}" -f "$OUTDIR/id_${keytype}"

keytype="ecdsa"
bits="256"
ssh-keygen -q -N "hunter2" -t "$keytype" -b "$bits" -C "${keytype}-${bits} (encrypted)" -f "$OUTDIR/id_${keytype}_${bits}_enc"
