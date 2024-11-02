#!/usr/bin/env bash

SCRIPT_DIR=$(cd "$(dirname "$0")" && pwd)
SCRIPT_NAME=$(basename "$0")

OUTDIR=$SCRIPT_DIR/../internal/file/testdata/rpm
[ -d "$OUTDIR" ] || mkdir -p "$OUTDIR"

RPM=${RPM:-$(which rpm)}
GPG=${GPG:-$(which gpg)}

generate_key() {
  alg=$1
  if [ "$alg" = "ECC" ] || [ "$alg" = "ECDSA" ] || [ "$alg" == "EdDSA" ]
  then
    keyparam="Key-Curve: $2"
  else
    keyparam="Key-Length: $2"
  fi

  "$GPG" --batch --generate-key <<EOF
     Key-Type: $alg
     $keyparam
     Name-Real: $1-$2
     Name-Email: $1.$2@example.com
     Expire-Date: 0
     %no-protection
     %commit
EOF
}

sign_rpm() {
  original=$1
  alg=$2
  size=$3
  hash=$4
  rpmfile="$(dirname "$original")/$alg-$size-$hash.rpm"
  cp "$original" "$rpmfile"
  rpmsign --addsign --rpmv3 \
    --define "_signature gpg" --define "_gpg_path $GNUPGHOME" --define "_gpg_name $alg-$size" \
    --define "__gpg_sign_cmd $GPG --batch --verbose --no-armor --no-secmem-warning -u \"%{_gpg_name}\" -sbo %{__signature_filename} --digest-algo $hash %{__plaintext_filename}" \
    "$rpmfile"
}

RPMBUILD_DIR=$(mktemp -d)
mkdir "$RPMBUILD_DIR/SPECS" || exit 1
cat > "$RPMBUILD_DIR/SPECS/dummy.spec" <<'EOF'
Name:           dummy
Version:        0.0.1
Release:        1%{?dist}
Summary:        A dummy RPM for signature testing
BuildArch:      noarch

License:        none

%description
This is a dummy RPM for testing the RPM parsing code in github.com/edutko/decipher.

%install
rm -rf "$RPM_BUILD_ROOT"
mkdir -p "$RPM_BUILD_ROOT"/%{_bindir}
cp %{_topdir}/script.sh "$RPM_BUILD_ROOT"/%{_bindir}

%clean
rm -rf "$RPM_BUILD_ROOT"

%files
%{_bindir}/script.sh

%changelog
* Sun Nov  3 2024 Firsty Lasterson <firsty.lasterson@example.com> - 0.0.1
- First version
EOF

cat > "$RPMBUILD_DIR/script.sh" <<EOF
echo "This is a dummy script from a dummy RPM intended for testing only."
EOF

rpmbuild -bb --define "_topdir $RPMBUILD_DIR" "$RPMBUILD_DIR/SPECS/dummy.spec"

mv "$RPMBUILD_DIR/RPMS/noarch/dummy-0.0.1-1.noarch.rpm" "$OUTDIR/unsigned.rpm"

rm -rf "$RPMBUILD_DIR"


GNUPGHOME=$(mktemp -d)
export GNUPGHOME

generate_key DSA 1024
generate_key RSA 2048
generate_key ECDSA nistp256

sign_rpm "$OUTDIR/unsigned.rpm" DSA 1024 sha1
sign_rpm "$OUTDIR/unsigned.rpm" RSA 2048 sha256

# ECDSA requires rpm 4.20.0 or later
#sign_rpm "$OUTDIR/unsigned.rpm" ECDSA nistp256 sha256

rm -rf "$GNUPGHOME"
