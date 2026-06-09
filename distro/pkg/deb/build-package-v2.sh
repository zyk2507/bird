#!/usr/bin/env bash

set -euo pipefail

usage()
{
	cat <<'EOF'
Usage: distro/pkg/deb/build-package-v2.sh [--output-dir DIR]

Build a minimal bird2 Debian package.

The package intentionally contains only:
  /usr/sbin/bird
  /usr/sbin/birdc
  /usr/sbin/birdcl
  /usr/lib/bird/prepare-environment
  /usr/lib/systemd/system/bird.service
  /etc/bird/bird.conf
  /etc/bird/envvars
  /etc/init.d/bird

Environment:
  DEB_VERSION   Package upstream version. Defaults to 2.19.0.
  DEB_RELEASE   CZ.NIC Debian release suffix used after "-cznic.".
                Defaults to 1~trixie.
EOF
}

repo_root="$(cd "$(dirname "$0")/../../.." && pwd)"
output_dir="$repo_root/../debian-artifacts"

while [ "$#" -gt 0 ]; do
	case "$1" in
		--output-dir)
			[ "$#" -ge 2 ] || { echo "Missing argument for --output-dir" >&2; exit 2; }
			output_dir="$2"
			shift 2
			;;
		-h|--help)
			usage
			exit 0
			;;
		*)
			echo "Unknown option: $1" >&2
			usage >&2
			exit 2
			;;
	esac
done

cd "$repo_root"

for tool in dpkg dpkg-deb make install nproc; do
	if ! command -v "$tool" >/dev/null 2>&1; then
		echo "$tool not found. Run this script in a Debian build environment." >&2
		exit 1
	fi
done

if [ ! -x ./configure ]; then
	if ! command -v autoreconf >/dev/null 2>&1; then
		echo "./configure is missing and autoreconf is not available." >&2
		exit 1
	fi
	autoreconf
fi

source_package="bird2"
version="${DEB_VERSION:-2.19.0}"
release="${DEB_RELEASE:-1~trixie}"
package_version="${version}-cznic.${release}"
arch="${DEB_ARCH:-$(dpkg --print-architecture)}"
build_dir="$repo_root/../${source_package}-minimal-deb-build"
pkgroot="$build_dir/pkg"
template_package="$source_package"

if [ ! -f "distro/pkg/deb/${template_package}.bird.init" ] ||
	[ ! -f "distro/pkg/deb/${template_package}.bird.service" ]; then
	template_package=""
	for candidate in bird3 bird2; do
		if [ -f "distro/pkg/deb/${candidate}.bird.init" ] &&
			[ -f "distro/pkg/deb/${candidate}.bird.service" ]; then
			template_package="$candidate"
			break
		fi
	done
fi

if [ -z "$template_package" ]; then
	echo "Debian init and systemd service templates are missing." >&2
	exit 1
fi

rm -rf "$build_dir"
mkdir -p "$build_dir"

tar \
	--exclude .git \
	--exclude debian \
	--exclude obj \
	--exclude bird \
	--exclude birdc \
	--exclude birdcl \
	--exclude config.log \
	--exclude config.status \
	-cf - . | tar -xf - -C "$build_dir"

cd "$build_dir"

./configure \
	--prefix=/usr \
	--sysconfdir=/etc/bird \
	--localstatedir=/var \
	--runstatedir=/run/bird \
	--enable-client \
	--with-protocols=all

make -j"$(nproc)"

install -Dm755 bird "$pkgroot/usr/sbin/bird"
install -Dm755 birdc "$pkgroot/usr/sbin/birdc"
install -Dm755 birdcl "$pkgroot/usr/sbin/birdcl"
install -Dm755 distro/pkg/deb/prepare-environment "$pkgroot/usr/lib/bird/prepare-environment"
install -Dm755 "distro/pkg/deb/${template_package}.bird.init" "$pkgroot/etc/init.d/bird"
install -Dm644 "distro/pkg/deb/${template_package}.bird.service" "$pkgroot/usr/lib/systemd/system/bird.service"
install -Dm644 doc/bird.conf.example "$pkgroot/etc/bird/bird.conf"
install -Dm644 distro/pkg/deb/envvars "$pkgroot/etc/bird/envvars"

mkdir -p "$pkgroot/DEBIAN"
cat > "$pkgroot/DEBIAN/conffiles" <<'EOF'
/etc/bird/bird.conf
/etc/bird/envvars
/etc/init.d/bird
EOF

cat > "$pkgroot/DEBIAN/postinst" <<'EOF'
#!/bin/sh
set -e

if [ "$1" = "configure" ]; then
	if ! getent passwd bird > /dev/null; then
		adduser --quiet --system --group --no-create-home --home /run/bird bird
	fi
fi

exit 0
EOF
chmod 755 "$pkgroot/DEBIAN/postinst"

installed_size="$(du -sk "$pkgroot" | cut -f1)"

cat > "$pkgroot/DEBIAN/control" <<EOF
Package: $source_package
Version: $package_version
Architecture: $arch
Maintainer: Maria Matejka <maria.matejka@nic.cz>
Installed-Size: $installed_size
Depends: adduser, libc6 (>= 2.38), libreadline8t64 (>= 6.0), libssh-4 (>= 0.8.0), libtinfo6 (>= 6)
Conflicts: bird
Section: net
Priority: optional
Homepage: https://bird.nic.cz/
Description: Internet Routing Daemon
 BIRD is an Internet routing daemon with support for major routing protocols.
 This minimal package ships only the daemon, clients, systemd and init.d
 service files, runtime helper, base configuration file, and environment
 file.
EOF

mkdir -p "$output_dir"
dpkg-deb --build --root-owner-group "$pkgroot" \
	"$output_dir/${source_package}_${package_version}_${arch}.deb"

echo "Debian artifact written to $output_dir/${source_package}_${package_version}_${arch}.deb"
