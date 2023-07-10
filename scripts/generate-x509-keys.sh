#!/usr/bin/env bash

OUTDIR=$(dirname "$0")/../internal/file/testdata/x509
[ -d "$OUTDIR" ] || mkdir -p "$OUTDIR"
[ -d "$OUTDIR/der" ] || mkdir -p "$OUTDIR/der"
[ -d "$OUTDIR/pem" ] || mkdir -p "$OUTDIR/pem"

for bits in 1024 2048
do
  rm "$OUTDIR/pem/dsa-${bits}"* "$OUTDIR/der/dsa-${bits}"*

  openssl dsaparam -out "$OUTDIR/pem/dsa-${bits}.param" $bits
  openssl gendsa -out "$OUTDIR/pem/dsa-${bits}.key" "$OUTDIR/pem/dsa-${bits}.param"
  openssl pkey -in "$OUTDIR/pem/dsa-${bits}.key" -outform der -out "$OUTDIR/der/dsa-${bits}.key"
  openssl dsa -in "$OUTDIR/pem/dsa-${bits}.key" -outform pem -out "$OUTDIR/pem/dsa-${bits}-dsa.key"
  openssl dsa -in "$OUTDIR/pem/dsa-${bits}.key" -outform der -out "$OUTDIR/der/dsa-${bits}-dsa.key"

  openssl pkey -in "$OUTDIR/pem/dsa-${bits}.key" -outform pem -pubout -out "$OUTDIR/pem/dsa-${bits}.pub"
  openssl pkey -in "$OUTDIR/pem/dsa-${bits}.key" -outform der -pubout -out "$OUTDIR/der/dsa-${bits}.pub"
done

for bits in 512 1024 2048 3072 4096
do
  rm "$OUTDIR/pem/rsa-${bits}"* "$OUTDIR/der/rsa-${bits}"*

  openssl genrsa -traditional -out "$OUTDIR/pem/rsa-${bits}-pkcs1.key" $bits
  openssl pkey -in "$OUTDIR/pem/rsa-${bits}-pkcs1.key" -outform der -out "$OUTDIR/der/rsa-${bits}-pkcs1.key"
  openssl pkcs8 -in "$OUTDIR/pem/rsa-${bits}-pkcs1.key" -topk8 -nocrypt -outform pem -out "$OUTDIR/pem/rsa-${bits}.key"
  openssl pkcs8 -in "$OUTDIR/pem/rsa-${bits}-pkcs1.key" -topk8 -nocrypt -outform der -out "$OUTDIR/der/rsa-${bits}.key"

  openssl pkey -in "$OUTDIR/pem/rsa-${bits}.key" -outform pem -pubout -out "$OUTDIR/pem/rsa-${bits}.pub"
  openssl pkey -in "$OUTDIR/pem/rsa-${bits}.key" -outform der -pubout -out "$OUTDIR/der/rsa-${bits}.pub"
  openssl rsa -in "$OUTDIR/pem/rsa-${bits}.key" -RSAPublicKey_out -outform pem -out "$OUTDIR/pem/rsa-${bits}-pkcs1.pub"
  openssl rsa -in "$OUTDIR/pem/rsa-${bits}.key" -RSAPublicKey_out -outform der -out "$OUTDIR/der/rsa-${bits}-pkcs1.pub"
done

for curve in secp224r1 prime256v1 secp384r1 secp521r1 sect233r1
do
  rm "$OUTDIR/pem/${curve}"* "$OUTDIR/der/${curve}"*

  openssl ecparam -name "$curve" -out "$OUTDIR/pem/${curve}.param"
  openssl ecparam -name "$curve" -param_enc explicit -out "$OUTDIR/pem/${curve}-explicit.param"

  openssl ecparam -name "$curve" -genkey -param_enc explicit -out "$OUTDIR/pem/${curve}-ec-explicit-withparams.key"
  openssl ec -in "$OUTDIR/pem/${curve}-ec-explicit-withparams.key" -outform pem -out "$OUTDIR/pem/${curve}-ec-explicit.key"

  openssl pkey -in "$OUTDIR/pem/${curve}-ec-explicit.key" -outform pem -pubout -out "$OUTDIR/pem/${curve}-explicit.pub"
  openssl pkey -in "$OUTDIR/pem/${curve}-ec-explicit.key" -outform der -pubout -out "$OUTDIR/der/${curve}-explicit.pub"

  openssl ecparam -name "$curve" -genkey -out "$OUTDIR/pem/${curve}-ec-withparams.key"
  openssl ec -in "$OUTDIR/pem/${curve}-ec-withparams.key" -outform pem -out "$OUTDIR/pem/${curve}-ec.key"
  openssl ec -in "$OUTDIR/pem/${curve}-ec-withparams.key" -outform der -out "$OUTDIR/der/${curve}-ec.key"
  openssl pkcs8 -in "$OUTDIR/pem/${curve}-ec.key" -topk8 -nocrypt -outform pem -out "$OUTDIR/pem/${curve}.key"
  openssl pkcs8 -in "$OUTDIR/pem/${curve}-ec.key" -topk8 -nocrypt -outform der -out "$OUTDIR/der/${curve}.key"

  openssl pkey -in "$OUTDIR/pem/${curve}.key" -outform pem -pubout -out "$OUTDIR/pem/${curve}.pub"
  openssl pkey -in "$OUTDIR/pem/${curve}.key" -outform der -pubout -out "$OUTDIR/der/${curve}.pub"
done

alg=ed25519
rm "$OUTDIR/pem/${alg}"* "$OUTDIR/der/${alg}"*
openssl genpkey -algorithm "$alg" -out "$OUTDIR/pem/${alg}.key"
openssl pkey -in "$OUTDIR/pem/${alg}.key" -outform der -out "$OUTDIR/der/${alg}.key"

openssl pkey -in "$OUTDIR/pem/${alg}.key" -outform pem -pubout -out "$OUTDIR/pem/${alg}.pub"
openssl pkey -in "$OUTDIR/pem/${alg}.key" -outform der -pubout -out "$OUTDIR/der/${alg}.pub"
