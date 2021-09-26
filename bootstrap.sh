#!/bin/sh

set -v
set -e
set -u

export DEB_BUILD_OPTIONS="nocheck noddebs parallel=1"
export DH_VERBOSE=1
HOST_ARCH=undefined
# select gcc version from gcc-defaults package unless set
GCC_VER=
: ${MIRROR:="http://http.debian.net/debian"}
ENABLE_MULTILIB=no
ENABLE_MULTIARCH_GCC=yes
REPODIR=/tmp/repo
APT_GET="apt-get --no-install-recommends -y -o Debug::pkgProblemResolver=true -o Debug::pkgDepCache::Marker=1 -o Debug::pkgDepCache::AutoInstall=1 -o Acquire::Languages=none -o Debug::BuildDeps=1"
DEFAULT_PROFILES="cross nocheck noinsttest noudeb"
LIBC_NAME=glibc
DROP_PRIVS=buildd
GCC_NOLANG="ada asan brig d gcn go itm java jit hppa64 lsan m2 nvptx objc obj-c++ tsan ubsan"
ENABLE_DIFFOSCOPE=no

if df -t tmpfs /var/cache/apt/archives >/dev/null 2>&1; then
	APT_GET="$APT_GET -o APT::Keep-Downloaded-Packages=false"
fi

if test "$(hostname -f)" = ionos9-amd64.debian.net; then
	# jenkin's proxy fails very often
	echo 'APT::Acquire::Retries "10";' > /etc/apt/apt.conf.d/80-retries
fi

# evaluate command line parameters of the form KEY=VALUE
for param in "$@"; do
	echo "bootstrap-configuration: $param"
	eval $param
done

# test whether element $2 is in set $1
set_contains() {
	case " $1 " in
		*" $2 "*) return 0; ;;
		*) return 1; ;;
	esac
}

# add element $2 to set $1
set_add() {
	case " $1 " in
		"  ") echo "$2" ;;
		*" $2 "*) echo "$1" ;;
		*) echo "$1 $2" ;;
	esac
}

# remove element $2 from set $1
set_discard() {
	local word result
	if set_contains "$1" "$2"; then
		result=
		for word in $1; do
			test "$word" = "$2" || result="$result $word"
		done
		echo "${result# }"
	else
		echo "$1"
	fi
}

# create a set from a string of words with duplicates and excess white space
set_create() {
	local word result
	result=
	for word in $1; do
		result=`set_add "$result" "$word"`
	done
	echo "$result"
}

# intersect two sets
set_intersect() {
	local word result
	result=
	for word in $1; do
		if set_contains "$2" "$word"; then
			result=`set_add "$result" "$word"`
		fi
	done
	echo "$result"
}

# compute the set of elements in set $1 but not in set $2
set_difference() {
	local word result
	result=
	for word in $1; do
		if ! set_contains "$2" "$word"; then
			result=`set_add "$result" "$word"`
		fi
	done
	echo "$result"
}

# compute the union of two sets $1 and $2
set_union() {
	local word result
	result=$1
	for word in $2; do
		result=`set_add "$result" "$word"`
	done
	echo "$result"
}

# join the words the arguments starting with $2 with separator $1
join_words() {
	local separator word result
	separator=$1
	shift
	result=
	for word in "$@"; do
		result="${result:+$result$separator}$word"
	done
	echo "$result"
}

check_arch() {
	if elf-arch -a "$2" "$1"; then
		return 0
	else
		case "$2:$(file -b "$1")" in
			"arc:ELF 32-bit LSB relocatable, ARC Cores Tangent-A5, version 1 (SYSV)"*)
				return 0
			;;
			"csky:ELF 32-bit LSB relocatable, *unknown arch 0xfc* version 1 (SYSV)"*)
				return 0
			;;
		esac
		echo "expected $2, but found $(file -b "$1")"
		return 1
	fi
}

filter_dpkg_tracked() {
	local pkg pkgs
	pkgs=""
	for pkg in "$@"; do
		dpkg-query -s "$pkg" >/dev/null 2>&1 && pkgs=`set_add "$pkgs" "$pkg"`
	done
	echo "$pkgs"
}

apt_get_install() {
	DEBIAN_FRONTEND=noninteractive $APT_GET install "$@"
}

apt_get_build_dep() {
	DEBIAN_FRONTEND=noninteractive $APT_GET build-dep "$@"
}

apt_get_remove() {
	local pkgs
	pkgs=$(filter_dpkg_tracked "$@")
	if test -n "$pkgs"; then
		$APT_GET remove $pkgs
	fi
}

apt_get_purge() {
	local pkgs
	pkgs=$(filter_dpkg_tracked "$@")
	if test -n "$pkgs"; then
		$APT_GET purge $pkgs
	fi
}

$APT_GET update
$APT_GET dist-upgrade # we need upgrade later, so make sure the system is clean
apt_get_install build-essential debhelper reprepro quilt arch-test

if test -z "$DROP_PRIVS"; then
	drop_privs_exec() {
		exec env -- "$@"
	}
else
	apt_get_install adduser fakeroot
	if ! getent passwd "$DROP_PRIVS" >/dev/null; then
		adduser --system --group --home /tmp/buildd --no-create-home --shell /bin/false "$DROP_PRIVS"
	fi
	drop_privs_exec() {
		exec /sbin/runuser --user "$DROP_PRIVS" --group "$DROP_PRIVS" -- /usr/bin/env -- "$@"
	}
fi
drop_privs() {
	( drop_privs_exec "$@" )
}

if test "$ENABLE_MULTIARCH_GCC" = yes; then
	apt_get_install cross-gcc-dev
	echo "removing unused unstripped_exe patch"
	sed -i '/made-unstripped_exe-setting-overridable/d' /usr/share/cross-gcc/patches/gcc-*/series
fi

obtain_source_package() {
	local use_experimental
	use_experimental=
	case "$1" in
		gcc-[0-9]*)
			test -n "$(apt-cache showsrc "$1")" || use_experimental=yes
		;;
	esac
	if test "$use_experimental" = yes; then
		echo "deb-src $MIRROR experimental main" > /etc/apt/sources.list.d/tmp-experimental.list
		$APT_GET update
	fi
	drop_privs apt-get source "$1"
	if test -f /etc/apt/sources.list.d/tmp-experimental.list; then
		rm /etc/apt/sources.list.d/tmp-experimental.list
		$APT_GET update
	fi
}

# #980963
cat <<EOF >> /usr/share/dpkg/cputable
arc		arc		arc		32	little
csky		csky		csky		32	little
EOF

if test -z "$HOST_ARCH" || ! dpkg-architecture "-a$HOST_ARCH"; then
	echo "architecture $HOST_ARCH unknown to dpkg"
	exit 1
fi

# ensure that the rebootstrap list comes first
test -f /etc/apt/sources.list && mv -v /etc/apt/sources.list /etc/apt/sources.list.d/local.list
for f in /etc/apt/sources.list.d/*.list; do
	test -f "$f" && sed -i "s/^deb \(\[.*\] \)*/deb [ arch-=$HOST_ARCH ] /" $f
done
grep -q '^deb-src .*sid' /etc/apt/sources.list.d/*.list || echo "deb-src $MIRROR sid main" >> /etc/apt/sources.list.d/sid-source.list

dpkg --add-architecture $HOST_ARCH
$APT_GET update

if test -z "$GCC_VER"; then
	GCC_VER=`apt-cache depends gcc | sed 's/^ *Depends: gcc-\([0-9.]*\)$/\1/;t;d'`
fi

rm -Rf /tmp/buildd
drop_privs mkdir -p /tmp/buildd

HOST_ARCH_SUFFIX="-`dpkg-architecture -a$HOST_ARCH -qDEB_HOST_GNU_TYPE | tr _ -`"

case "$HOST_ARCH" in
	amd64) MULTILIB_NAMES="i386 x32" ;;
	i386) MULTILIB_NAMES="amd64 x32" ;;
	mips|mipsel) MULTILIB_NAMES="mips64 mipsn32" ;;
	mips64|mips64el) MULTILIB_NAMES="mips32 mipsn32" ;;
	mipsn32|mipsn32el) MULTILIB_NAMES="mips32 mips64" ;;
	powerpc) MULTILIB_NAMES=ppc64 ;;
	ppc64) MULTILIB_NAMES=powerpc ;;
	s390x) MULTILIB_NAMES=s390 ;;
	sparc) MULTILIB_NAMES=sparc64 ;;
	sparc64) MULTILIB_NAMES=sparc ;;
	x32) MULTILIB_NAMES="amd64 i386" ;;
	*) MULTILIB_NAMES="" ;;
esac
if test "$ENABLE_MULTILIB" != yes; then
	MULTILIB_NAMES=""
fi

mkdir -p "$REPODIR/conf" "$REPODIR/archive" "$REPODIR/stamps"
cat > "$REPODIR/conf/distributions" <<EOF
Codename: rebootstrap
Label: rebootstrap
Architectures: `dpkg --print-architecture` $HOST_ARCH
Components: main
UDebComponents: main
Description: cross toolchain and build results for $HOST_ARCH

Codename: rebootstrap-native
Label: rebootstrap-native
Architectures: `dpkg --print-architecture`
Components: main
UDebComponents: main
Description: native packages needed for bootstrap
EOF
cat > "$REPODIR/conf/options" <<EOF
verbose
ignore wrongdistribution
EOF
export REPREPRO_BASE_DIR="$REPODIR"
reprepro export
echo "deb [ arch=$(dpkg --print-architecture),$HOST_ARCH trusted=yes ] file://$REPODIR rebootstrap main" >/etc/apt/sources.list.d/000_rebootstrap.list
echo "deb [ arch=$(dpkg --print-architecture) trusted=yes ] file://$REPODIR rebootstrap-native main" >/etc/apt/sources.list.d/001_rebootstrap-native.list
cat >/etc/apt/preferences.d/rebootstrap.pref <<EOF
Explanation: prefer our own rebootstrap (native) packages over everything
Package: *
Pin: release l=rebootstrap-native
Pin-Priority: 1001

Explanation: prefer our own rebootstrap (toolchain) packages over everything
Package: *
Pin: release l=rebootstrap
Pin-Priority: 1002

Explanation: do not use archive cross toolchain
Package: *-$HOST_ARCH-cross *$HOST_ARCH_SUFFIX gcc-*$HOST_ARCH_SUFFIX-base
Pin: release a=unstable
Pin-Priority: -1
EOF
$APT_GET update

# Since most libraries (e.g. libgcc_s) do not include ABI-tags,
# glibc may be confused and try to use them. A typical symptom is:
# apt-get: error while loading shared libraries: /lib/x86_64-kfreebsd-gnu/libgcc_s.so.1: ELF file OS ABI invalid
cat >/etc/dpkg/dpkg.cfg.d/ignore-foreign-linker-paths <<EOF
path-exclude=/etc/ld.so.conf.d/$(dpkg-architecture "-a$HOST_ARCH" -qDEB_HOST_MULTIARCH).conf
EOF

# Work around Multi-Arch: same file conflict in libxdmcp-dev. #825146
cat >/etc/dpkg/dpkg.cfg.d/bug-825146 <<'EOF'
path-exclude=/usr/share/doc/libxdmcp-dev/xdmcp.txt.gz
EOF

# Work around binNMU file conflicts of e.g. binutils or gcc.
cat >/etc/dpkg/dpkg.cfg.d/binNMU-changelogs <<EOF
path-exclude=/usr/share/doc/*/changelog.Debian.$(dpkg-architecture -qDEB_BUILD_ARCH).gz
EOF

if test "$HOST_ARCH" = nios2; then
	echo "fixing libtool's nios2 misdetection as os2 #851253"
	apt_get_install libtool
	sed -i -e 's/\*os2\*/*-os2*/' /usr/share/libtool/build-aux/ltmain.sh
fi

# removing libc*-dev conflict with each other
LIBC_DEV_PKG=$(apt-cache showpkg libc-dev | sed '1,/^Reverse Provides:/d;s/ .*//;q')
if test "$(apt-cache show "$LIBC_DEV_PKG" | sed -n 's/^Source: //;T;p;q')" = glibc; then
if test -f "$REPODIR/pool/main/g/glibc/$LIBC_DEV_PKG"_*_"$(dpkg --print-architecture).deb"; then
	dpkg -i "$REPODIR/pool/main/g/glibc/$LIBC_DEV_PKG"_*_"$(dpkg --print-architecture).deb"
else
	cd /tmp/buildd
	apt-get download "$LIBC_DEV_PKG"
	dpkg-deb -R "./$LIBC_DEV_PKG"_*.deb x
	sed -i -e '/^Conflicts: /d' x/DEBIAN/control
	mv -nv -t x/usr/include "x/usr/include/$(dpkg-architecture -qDEB_HOST_MULTIARCH)/"*
	mv -nv x/usr/include x/usr/include.orig
	mkdir x/usr/include
	mv -nv x/usr/include.orig "x/usr/include/$(dpkg-architecture -qDEB_HOST_MULTIARCH)"
	dpkg-deb -b x "./$LIBC_DEV_PKG"_*.deb
	reprepro includedeb rebootstrap-native "./$LIBC_DEV_PKG"_*.deb
	dpkg -i "./$LIBC_DEV_PKG"_*.deb
	$APT_GET update
	rm -R "./$LIBC_DEV_PKG"_*.deb x
fi # already repacked
fi # is glibc

chdist_native() {
	local command
	command="$1"
	shift
	chdist --data-dir /tmp/chdist_native --arch "$HOST_ARCH" "$command" native "$@"
}

if test "$ENABLE_DIFFOSCOPE" = yes; then
	apt_get_install devscripts
	chdist_native create "$MIRROR" sid main
	if ! chdist_native apt-get update; then
		echo "rebootstrap-warning: not comparing packages to native builds"
		rm -Rf /tmp/chdist_native
		ENABLE_DIFFOSCOPE=no
	fi
fi
if test "$ENABLE_DIFFOSCOPE" = yes; then
	compare_native() {
		local pkg pkgname tmpdir downloadname errcode
		apt_get_install diffoscope binutils-multiarch vim-common
		for pkg in "$@"; do
			if test "`dpkg-deb -f "$pkg" Architecture`" != "$HOST_ARCH"; then
				echo "not comparing $pkg: wrong architecture"
				continue
			fi
			pkgname=`dpkg-deb -f "$pkg" Package`
			tmpdir=`mktemp -d`
			mkdir "$tmpdir/a" "$tmpdir/b"
			cp "$pkg" "$tmpdir/a" # work around diffoscope recursing over the build tree
			if ! (cd "$tmpdir/b" && chdist_native apt-get download "$pkgname"); then
				echo "not comparing $pkg: download failed"
				rm -R "$tmpdir"
				continue
			fi
			downloadname=`dpkg-deb -W --showformat '${Package}_${Version}_${Architecture}.deb' "$pkg" | sed 's/:/%3a/'`
			if ! test -f "$tmpdir/b/$downloadname"; then
				echo "not comparing $pkg: downloaded different version"
				rm -R "$tmpdir"
				continue
			fi
			errcode=0
			timeout --kill-after=1m 1h diffoscope --text "$tmpdir/out" "$tmpdir/a/$(basename -- "$pkg")" "$tmpdir/b/$downloadname" || errcode=$?
			case $errcode in
				0)
					echo "diffoscope-success: $pkg"
				;;
				1)
					if ! test -f "$tmpdir/out"; then
						echo "rebootstrap-error: no diffoscope output for $pkg"
						exit 1
					elif test "`wc -l < "$tmpdir/out"`" -gt 1000; then
						echo "truncated diffoscope output for $pkg:"
						head -n1000 "$tmpdir/out"
					else
						echo "diffoscope output for $pkg:"
						cat "$tmpdir/out"
					fi
				;;
				124)
					echo "rebootstrap-warning: diffoscope timed out"
				;;
				*)
					echo "rebootstrap-error: diffoscope terminated with abnormal exit code $errcode"
					exit 1
				;;
			esac
			rm -R "$tmpdir"
		done
	}
else
	compare_native() { :
	}
fi

pickup_additional_packages() {
	local f
	for f in "$@"; do
		if test "${f%.deb}" != "$f"; then
			reprepro includedeb rebootstrap "$f"
		elif test "${f%.changes}" != "$f"; then
			reprepro include rebootstrap "$f"
		else
			echo "cannot pick up package $f"
			exit 1
		fi
	done
	$APT_GET update
}

pickup_packages() {
	local sources
	local source
	local f
	local i
	# collect source package names referenced
	sources=""
	for f in "$@"; do
		if test "${f%.deb}" != "$f"; then
			source=`dpkg-deb -f "$f" Source`
			test -z "$source" && source=${f%%_*}
		elif test "${f%.changes}" != "$f"; then
			source=${f%%_*}
		else
			echo "cannot pick up package $f"
			exit 1
		fi
		sources=`set_add "$sources" "$source"`
	done
	# archive old contents and remove them from the repository
	for source in $sources; do
		i=1
		while test -e "$REPODIR/archive/${source}_$i"; do
			i=`expr $i + 1`
		done
		i="$REPODIR/archive/${source}_$i"
		mkdir "$i"
		for f in $(reprepro --list-format '${Filename}\n' listfilter rebootstrap "\$Source (== $source)"); do
			cp -v "$REPODIR/$f" "$i"
		done
		find "$i" -type d -empty -delete
		reprepro removesrc rebootstrap "$source"
	done
	# add new contents
	pickup_additional_packages "$@"
}

# compute a function name from a hook prefix $1 and a package name $2
# returns success if the function actually exists
get_hook() {
	local hook
	hook=`echo "$2" | tr -- -. __` # - and . are invalid in function names
	hook="${1}_$hook"
	echo "$hook"
	type "$hook" >/dev/null 2>&1 || return 1
}

cross_build_setup() {
	local pkg subdir hook
	pkg="$1"
	subdir="${2:-$pkg}"
	cd /tmp/buildd
	drop_privs mkdir "$subdir"
	cd "$subdir"
	obtain_source_package "$pkg"
	cd "${pkg}-"*
	hook=`get_hook patch "$pkg"` && "$hook"
	return 0
}

# add a binNMU changelog entry
# . is a debian package
# $1 is the binNMU number
# $2 is reason
add_binNMU_changelog() {
	cat - debian/changelog <<EOF |
$(dpkg-parsechangelog -SSource) ($(dpkg-parsechangelog -SVersion)+b$1) sid; urgency=medium, binary-only=yes

  * Binary-only non-maintainer upload for $HOST_ARCH; no source changes.
  * $2

 -- rebootstrap <invalid@invalid>  $(dpkg-parsechangelog -SDate)

EOF
		drop_privs tee debian/changelog.new >/dev/null
	drop_privs mv debian/changelog.new debian/changelog
}

check_binNMU() {
	local pkg srcversion binversion maxversion
	srcversion=`dpkg-parsechangelog -SVersion`
	maxversion=$srcversion
	for pkg in `dh_listpackages`; do
		binversion=`apt-cache show "$pkg=$srcversion*" 2>/dev/null | sed -n 's/^Version: //p;T;q'`
		test -z "$binversion" && continue
		if dpkg --compare-versions "$maxversion" lt "$binversion"; then
			maxversion=$binversion
		fi
	done
	case "$maxversion" in
		"$srcversion+b"*)
			echo "rebootstrap-warning: binNMU detected for $(dpkg-parsechangelog -SSource) $srcversion/$maxversion"
			add_binNMU_changelog "${maxversion#$srcversion+b}" "Bump to binNMU version of $(dpkg --print-architecture)."
		;;
	esac
}

PROGRESS_MARK=1
progress_mark() {
	echo "progress-mark:$PROGRESS_MARK:$*"
	PROGRESS_MARK=$(($PROGRESS_MARK + 1 ))
}

# prints the set (as in set_create) of installed packages
record_installed_packages() {
	dpkg --get-selections | sed 's/\s\+install$//;t;d' | xargs
}

# Takes the set (as in set_create) of packages and apt-get removes any
# currently installed packages outside the given set.
remove_extra_packages() {
	local origpackages currentpackages removedpackages extrapackages
	origpackages="$1"
	currentpackages=$(record_installed_packages)
	removedpackages=$(set_difference "$origpackages" "$currentpackages")
	extrapackages=$(set_difference "$currentpackages" "$origpackages")
	echo "original packages: $origpackages"
	echo "removed packages:  $removedpackages"
	echo "extra packages:    $extrapackages"
	apt_get_remove $extrapackages
}

buildpackage_failed() {
	local err last_config_log
	err="$1"
	echo "rebootstrap-error: dpkg-buildpackage failed with status $err"
	last_config_log=$(find . -type f -name config.log -printf "%T@ %p\n" | sort -g | tail -n1 | cut "-d " -f2-)
	if test -f "$last_config_log"; then
		tail -v -n+0 "$last_config_log"
	fi
	exit "$err"
}

cross_build() {
	local pkg profiles stamp ignorebd hook installedpackages
	pkg="$1"
	profiles="$DEFAULT_PROFILES ${2:-}"
	stamp="${3:-$pkg}"
	if test "$ENABLE_MULTILIB" = "no"; then
		profiles="$profiles nobiarch"
	fi
	profiles=$(join_words , $profiles)
	if test -f "$REPODIR/stamps/$stamp"; then
		echo "skipping rebuild of $pkg with profiles $profiles"
	else
		echo "building $pkg with profiles $profiles"
		cross_build_setup "$pkg" "$stamp"
		installedpackages=$(record_installed_packages)
		if hook=`get_hook builddep "$pkg"`; then
			echo "installing Build-Depends for $pkg using custom function"
			"$hook" "$HOST_ARCH" "$profiles"
		else
			echo "installing Build-Depends for $pkg using apt-get build-dep"
			apt_get_build_dep "-a$HOST_ARCH" --arch-only -P "$profiles" ./
		fi
		check_binNMU
		ignorebd=
		if get_hook builddep "$pkg" >/dev/null; then
			if dpkg-checkbuilddeps -B "-a$HOST_ARCH" -P "$profiles"; then
				echo "rebootstrap-warning: Build-Depends for $pkg satisfied even though a custom builddep_  function is in use"
			fi
			ignorebd=-d
		fi
		(
			if hook=`get_hook buildenv "$pkg"`; then
				echo "adding environment variables via buildenv hook for $pkg"
				"$hook" "$HOST_ARCH"
			fi
			drop_privs_exec dpkg-buildpackage "-a$HOST_ARCH" -B "-P$profiles" $ignorebd -uc -us
		) || buildpackage_failed "$?"
		cd ..
		remove_extra_packages "$installedpackages"
		ls -l
		pickup_packages *.changes
		touch "$REPODIR/stamps/$stamp"
		compare_native ./*.deb
		cd ..
		drop_privs rm -Rf "$stamp"
	fi
	progress_mark "$stamp cross build"
}

case "$HOST_ARCH" in
	musl-linux-*) LIBC_NAME=musl ;;
esac

if test "$ENABLE_MULTIARCH_GCC" != yes; then
	apt_get_install dpkg-cross
fi

automatic_packages=
add_automatic() { automatic_packages=$(set_add "$automatic_packages" "$1"); }

add_automatic acl
add_automatic apt
add_automatic attr
add_automatic autogen
add_automatic base-files
add_automatic base-passwd

add_automatic bash
builddep_bash() {
	echo "working around libncurses-dev conflict #986764"
	apt_get_remove libncurses-dev
	apt_get_build_dep "-a$1" --arch-only -P "$2" ./
}

patch_binutils() {
	echo "patching binutils to discard ldscripts"
	# They cause file conflicts with binutils and the in-archive cross
	# binutils discard ldscripts as well.
	drop_privs patch -p1 <<'EOF'
--- a/debian/rules
+++ b/debian/rules
@@ -751,6 +751,7 @@
 		mandir=$(pwd)/$(D_CROSS)/$(PF)/share/man install
 
 	rm -rf \
+		$(D_CROSS)/$(PF)/lib/ldscripts \
 		$(D_CROSS)/$(PF)/share/info \
 		$(D_CROSS)/$(PF)/share/locale
 
EOF
	if test "$HOST_ARCH" = hppa; then
		echo "patching binutils to discard hppa64 ldscripts"
		# They cause file conflicts with binutils and the in-archive
		# cross binutils discard ldscripts as well.
		drop_privs patch -p1 <<'EOF'
--- a/debian/rules
+++ b/debian/rules
@@ -1233,6 +1233,7 @@
 		$(d_hppa64)/$(PF)/lib/$(DEB_HOST_MULTIARCH)/.

 	: # Now get rid of just about everything in binutils-hppa64
+	rm -rf $(d_hppa64)/$(PF)/lib/ldscripts
 	rm -rf $(d_hppa64)/$(PF)/man
 	rm -rf $(d_hppa64)/$(PF)/info
 	rm -rf $(d_hppa64)/$(PF)/include
EOF
	fi
	echo "fix honouring of nocheck option #990794"
	drop_privs sed -i -e 's/ifeq (\(,$(filter $(DEB_HOST_ARCH),\)/ifneq ($(DEB_BUILD_ARCH)\1/' debian/rules
	case "$HOST_ARCH" in nios2|sparc)
		echo "enabling uncommon architectures in debian/control"
		drop_privs sed -i -e "/^#NATIVE_ARCHS +=/aNATIVE_ARCHS += $HOST_ARCH" debian/rules
		drop_privs ./debian/rules ./stamps/control
		drop_privs rm -f ./stamps/control
	;; esac
	echo "fix undefined symbol ldlex_defsym #992318"
	rm -f ld/ldlex.c
}

add_automatic blt

add_automatic bsdmainutils
patch_bsdmainutils() {
	dpkg-architecture "-a$HOST_ARCH" -imusl-linux-any || return 0
	echo "fixing FTBFS on musl-linux-any #989688"
	drop_privs sed -i -e '/__unused/d' freebsd.h
}

builddep_build_essential() {
	# g++ dependency needs cross translation
	apt_get_install debhelper python3
}

add_automatic bzip2
add_automatic c-ares
add_automatic coreutils

add_automatic curl
builddep_curl() {
	echo "don't enable zstd support in curl #992505"
	apt_get_purge libzstd-dev
	apt_get_build_dep "-a$1" --arch-only -P "$2" ./
}

patch_cyrus_sasl2() {
	echo "fix build-depends #928512"
	drop_privs patch -p1 <<'EOF'
--- a/debian/control
+++ b/debian/control
@@ -18,12 +18,12 @@
                libkrb5-dev <!pkg.cyrus-sasl2.nogssapi>,
                libldap2-dev <!pkg.cyrus-sasl2.noldap>,
                libpam0g-dev,
-               libpod-pom-view-restructured-perl,
+               libpod-pom-view-restructured-perl:native,
                libpq-dev <!pkg.cyrus-sasl2.nosql>,
                libsqlite3-dev,
                libssl-dev,
                po-debconf,
-               python3-sphinx,
+               python3-sphinx:native,
                quilt
 Build-Conflicts: heimdal-dev
 Vcs-Browser: https://salsa.debian.org/debian/cyrus-sasl2
EOF
}

add_automatic dash
add_automatic db-defaults
add_automatic debianutils

add_automatic diffutils
buildenv_diffutils() {
	if dpkg-architecture "-a$1" -ignu-any-any; then
		export gl_cv_func_getopt_gnu=yes
	fi
}

add_automatic dpkg
add_automatic e2fsprogs
add_automatic expat
add_automatic file
add_automatic findutils
add_automatic flex
add_automatic fontconfig
add_automatic freetype
add_automatic fribidi
add_automatic fuse

patch_gcc_default_pie_everywhere()
{
	echo "enabling pie everywhere #892281"
	drop_privs patch -p1 <<'EOF'
--- a/debian/rules.defs
+++ a/debian/rules.defs
@@ -1250,9 +1250,7 @@
     pie_archs += armhf arm64 i386
   endif
 endif
-ifneq (,$(filter $(DEB_TARGET_ARCH),$(pie_archs)))
-  with_pie := yes
-endif
+with_pie := yes
 ifeq ($(trunk_build),yes)
   with_pie := disabled for trunk builds
 endif
EOF
}
patch_gcc_limits_h_test() {
	echo "fix LIMITS_H_TEST again https://gcc.gnu.org/bugzilla/show_bug.cgi?id=80677"
	drop_privs tee debian/patches/limits-h-test.diff >/dev/null <<'EOF'
--- a/src/gcc/limitx.h
+++ b/src/gcc/limitx.h
@@ -29,7 +29,7 @@
 #ifndef _GCC_LIMITS_H_  /* Terminated in limity.h.  */
 #define _GCC_LIMITS_H_

-#ifndef _LIBC_LIMITS_H_
+#if !defined(_LIBC_LIMITS_H_) && __has_include_next(<limits.h>)
 /* Use "..." so that we find syslimits.h only in this same directory.  */
 #include "syslimits.h"
 #endif
--- a/src/gcc/limity.h
+++ b/src/gcc/limity.h
@@ -3,7 +3,7 @@

 #else /* not _GCC_LIMITS_H_ */

-#ifdef _GCC_NEXT_LIMITS_H
+#if defined(_GCC_NEXT_LIMITS_H) && __has_include_next(<limits.h>)
 #include_next <limits.h>		/* recurse down to the real one */
 #endif

--- a/src/gcc/Makefile.in
+++ b/src/gcc/Makefile.in
@@ -3139,11 +3139,7 @@
 	  sysroot_headers_suffix=`echo $${ml} | sed -e 's/;.*$$//'`; \
 	  multi_dir=`echo $${ml} | sed -e 's/^[^;]*;//'`; \
 	  fix_dir=include-fixed$${multi_dir}; \
-	  if $(LIMITS_H_TEST) ; then \
-	    cat $(srcdir)/limitx.h $(T_GLIMITS_H) $(srcdir)/limity.h > tmp-xlimits.h; \
-	  else \
-	    cat $(T_GLIMITS_H) > tmp-xlimits.h; \
-	  fi; \
+	  cat $(srcdir)/limitx.h $(T_GLIMITS_H) $(srcdir)/limity.h > tmp-xlimits.h; \
 	  $(mkinstalldirs) $${fix_dir}; \
 	  chmod a+rx $${fix_dir} || true; \
 	  $(SHELL) $(srcdir)/../move-if-change \
EOF
	if test "$GCC_VER" = 10; then
		drop_privs sed -i -e 's,\$(T_GLIMITS_H),$(srcdir)/glimits.h,' debian/patches/limits-h-test.diff
	fi
	echo "debian_patches += limits-h-test" | drop_privs tee -a debian/rules.patch >/dev/null
}
patch_gcc_wdotap() {
	if test "$ENABLE_MULTIARCH_GCC" = yes; then
		echo "applying patches for with_deps_on_target_arch_pkgs"
		drop_privs rm -Rf .pc
		drop_privs QUILT_PATCHES="/usr/share/cross-gcc/patches/gcc-$GCC_VER" quilt push -a
		drop_privs rm -Rf .pc
	fi
}
patch_gcc_10() {
	patch_gcc_default_pie_everywhere
	patch_gcc_limits_h_test
	drop_privs sed -i -e 's/^\s*#\?\(with_common_libs\s*:\?=\).*/\1yes/' debian/rules.defs
	patch_gcc_wdotap
}
patch_gcc_11() {
	patch_gcc_limits_h_test
	patch_gcc_default_pie_everywhere
	patch_gcc_wdotap
}

buildenv_gdbm() {
	if dpkg-architecture "-a$1" -ignu-any-any; then
		export ac_cv_func_mmap_fixed_mapped=yes
	fi
}

add_automatic glib2.0

builddep_glibc() {
	test "$1" = "$HOST_ARCH"
	apt_get_install gettext file quilt autoconf gawk debhelper rdfind symlinks binutils bison netbase "gcc-$GCC_VER$HOST_ARCH_SUFFIX"
	case "$(dpkg-architecture "-a$1" -qDEB_HOST_ARCH_OS)" in
		linux)
			if test "$ENABLE_MULTIARCH_GCC" = yes; then
				apt_get_install "linux-libc-dev:$HOST_ARCH"
			else
				apt_get_install "linux-libc-dev-$HOST_ARCH-cross"
			fi
		;;
		hurd)
			apt_get_install "gnumach-dev:$1" "hurd-headers-dev:$1" "mig$HOST_ARCH_SUFFIX"
		;;
		*)
			echo "rebootstrap-error: unsupported kernel"
			exit 1
		;;
	esac
	if test "$1" = csky; then
		echo "adding csky support to config.sub #989944"
		sed -i -e 's/\(| cydra-\* \)\\/\1| csky-* \\/;s/\(| clipper \)\\/\1| csky \\/' /usr/share/misc/config.sub
	fi
}
patch_glibc() {
	echo "patching glibc to pass -l to dh_shlibdeps for multilib"
	drop_privs patch -p1 <<'EOF'
diff -Nru glibc-2.19/debian/rules.d/debhelper.mk glibc-2.19/debian/rules.d/debhelper.mk
--- glibc-2.19/debian/rules.d/debhelper.mk
+++ glibc-2.19/debian/rules.d/debhelper.mk
@@ -109,7 +109,7 @@
 	./debian/shlibs-add-udebs $(curpass)
 
 	dh_installdeb -p$(curpass)
-	dh_shlibdeps -p$(curpass)
+	dh_shlibdeps $(if $($(lastword $(subst -, ,$(curpass)))_slibdir),-l$(CURDIR)/debian/$(curpass)/$($(lastword $(subst -, ,$(curpass)))_slibdir)) -p$(curpass)
 	dh_gencontrol -p$(curpass)
 	if [ $(curpass) = nscd ] ; then \
 		sed -i -e "s/\(Depends:.*libc[0-9.]\+\)-[a-z0-9]\+/\1/" debian/nscd/DEBIAN/control ; \
EOF
	echo "patching glibc to find standard linux headers"
	drop_privs patch -p1 <<'EOF'
diff -Nru glibc-2.19/debian/sysdeps/linux.mk glibc-2.19/debian/sysdeps/linux.mk
--- glibc-2.19/debian/sysdeps/linux.mk
+++ glibc-2.19/debian/sysdeps/linux.mk
@@ -16,7 +16,7 @@
 endif

 ifndef LINUX_SOURCE
-  ifeq ($(DEB_HOST_GNU_TYPE),$(DEB_BUILD_GNU_TYPE))
+  ifeq ($(shell dpkg-query --status linux-libc-dev-$(DEB_HOST_ARCH)-cross 2>/dev/null),)
     LINUX_HEADERS := /usr/include
   else
     LINUX_HEADERS := /usr/$(DEB_HOST_GNU_TYPE)/include
EOF
	if ! sed -n '/^libc6_archs *:=/,/[^\\]$/p' debian/rules.d/control.mk | grep -qw "$HOST_ARCH"; then
		echo "adding $HOST_ARCH to libc6_archs"
		drop_privs sed -i -e "s/^libc6_archs *:= /&$HOST_ARCH /" debian/rules.d/control.mk
		drop_privs ./debian/rules debian/control
	fi
	echo "patching glibc to drop dev package conflict"
	sed -i -e '/^Conflicts: @libc-dev-conflict@$/d' debian/control.in/libc
	echo "patching glibc to move all headers to multiarch locations #798955"
	drop_privs patch -p1 <<'EOF'
--- a/debian/rules.d/build.mk
+++ b/debian/rules.d/build.mk
@@ -4,12 +4,16 @@
 xx=$(if $($(curpass)_$(1)),$($(curpass)_$(1)),$($(1)))
 define generic_multilib_extra_pkg_install
 set -e; \
-mkdir -p debian/$(1)/usr/include/sys; \
-ln -sf $(DEB_HOST_MULTIARCH)/bits debian/$(1)/usr/include/; \
-ln -sf $(DEB_HOST_MULTIARCH)/gnu debian/$(1)/usr/include/; \
-ln -sf $(DEB_HOST_MULTIARCH)/fpu_control.h debian/$(1)/usr/include/; \
-for i in `ls debian/tmp-libc/usr/include/$(DEB_HOST_MULTIARCH)/sys`; do \
-	ln -sf ../$(DEB_HOST_MULTIARCH)/sys/$$i debian/$(1)/usr/include/sys/$$i; \
+mkdir -p debian/$(1)/usr/include; \
+for i in `ls debian/tmp-libc/usr/include/$(DEB_HOST_MULTIARCH)`; do \
+	if test -d "debian/tmp-libc/usr/include/$(DEB_HOST_MULTIARCH)/$$i" && ! test "$$i" = bits -o "$$i" = gnu; then \
+		mkdir -p "debian/$(1)/usr/include/$$i"; \
+		for j in `ls debian/tmp-libc/usr/include/$(DEB_HOST_MULTIARCH)/$$i`; do \
+			ln -sf "../$(DEB_HOST_MULTIARCH)/$$i/$$j" "debian/$(1)/usr/include/$$i/$$j"; \
+		done; \
+	else \
+		ln -sf "$(DEB_HOST_MULTIARCH)/$$i" "debian/$(1)/usr/include/$$i"; \
+	fi; \
 done
 endef
 
@@ -218,15 +218,11 @@
 	    echo "/lib/$(DEB_HOST_GNU_TYPE)" >> $$conffile; \
 	    echo "/usr/lib/$(DEB_HOST_GNU_TYPE)" >> $$conffile; \
 	  fi; \
-	  mkdir -p debian/tmp-$(curpass)/usr/include/$(DEB_HOST_MULTIARCH); \
-	  mv debian/tmp-$(curpass)/usr/include/bits debian/tmp-$(curpass)/usr/include/$(DEB_HOST_MULTIARCH); \
-	  mv debian/tmp-$(curpass)/usr/include/gnu debian/tmp-$(curpass)/usr/include/$(DEB_HOST_MULTIARCH); \
-	  mv debian/tmp-$(curpass)/usr/include/sys debian/tmp-$(curpass)/usr/include/$(DEB_HOST_MULTIARCH); \
-	  mv debian/tmp-$(curpass)/usr/include/fpu_control.h debian/tmp-$(curpass)/usr/include/$(DEB_HOST_MULTIARCH); \
-	  mv debian/tmp-$(curpass)/usr/include/a.out.h debian/tmp-$(curpass)/usr/include/$(DEB_HOST_MULTIARCH); \
-	  mv debian/tmp-$(curpass)/usr/include/ieee754.h debian/tmp-$(curpass)/usr/include/$(DEB_HOST_MULTIARCH); \
+	  mkdir -p debian/tmp-$(curpass)/usr/include.tmp; \
+	  mv debian/tmp-$(curpass)/usr/include debian/tmp-$(curpass)/usr/include.tmp/$(DEB_HOST_MULTIARCH); \
+	  mv debian/tmp-$(curpass)/usr/include.tmp debian/tmp-$(curpass)/usr/include; \
 	  mkdir -p debian/tmp-$(curpass)/usr/include/finclude/$(DEB_HOST_MULTIARCH); \
-	  mv debian/tmp-$(curpass)/usr/include/finclude/math-vector-fortran.h debian/tmp-$(curpass)/usr/include/finclude/$(DEB_HOST_MULTIARCH); \
+	  mv debian/tmp-$(curpass)/usr/include/$(DEB_HOST_MULTIARCH)/finclude/math-vector-fortran.h debian/tmp-$(curpass)/usr/include/finclude/$(DEB_HOST_MULTIARCH); \
 	fi
 
 	ifeq ($(filter stage1,$(DEB_BUILD_PROFILES)),)
--- a/debian/sysdeps/hurd-i386.mk
+++ b/debian/sysdeps/hurd-i386.mk
@@ -18,9 +18,6 @@ endif
 define libc_extra_install
 mkdir -p debian/tmp-$(curpass)/lib
 ln -s ld.so.1 debian/tmp-$(curpass)/lib/ld.so
-mkdir -p debian/tmp-$(curpass)/usr/include/$(DEB_HOST_MULTIARCH)/mach
-mv debian/tmp-$(curpass)/usr/include/mach/i386 debian/tmp-$(curpass)/usr/include/$(DEB_HOST_MULTIARCH)/mach/
-ln -s ../$(DEB_HOST_MULTIARCH)/mach/i386 debian/tmp-$(curpass)/usr/include/mach/i386
 endef
 
 # FIXME: We are having runtime issues with ifunc...
EOF
	echo "patching glibc to avoid -Werror"
	drop_privs patch -p1 <<'EOF'
--- a/debian/rules.d/build.mk
+++ b/debian/rules.d/build.mk
@@ -85,6 +85,7 @@
 		$(CURDIR)/configure \
 		--host=$(call xx,configure_target) \
 		--build=$$configure_build --prefix=/usr \
+		--disable-werror \
 		--enable-add-ons=$(standard-add-ons)"$(call xx,add-ons)" \
 		--without-selinux \
 		--enable-stackguard-randomization \
EOF
	if test "$HOST_ARCH" = alpha; then
		echo "cherry-picking glibc alpha patch for struct stat"
		drop_privs patch -p1 <<'EOF'
From d552058570ea2c00fb88b4621be3285cda03033f Mon Sep 17 00:00:00 2001
From: Matt Turner <mattst88@gmail.com>
Date: Mon, 21 Dec 2020 09:09:43 -0300
Subject: [PATCH] alpha: Remove anonymous union in struct stat [BZ #27042]

This is clever, but it confuses downstream detection in at least zstd
and GNOME's glib. zstd has preprocessor tests for the 'st_mtime' macro,
which is not provided by the path using the anonymous union; glib checks
for the presence of 'st_mtimensec' in struct stat but then tries to
access that field in struct statx (which might be a bug on its own).

Checked with a build for alpha-linux-gnu.
---
 .../unix/sysv/linux/alpha/bits/struct_stat.h  | 81 ++++++++++---------
 sysdeps/unix/sysv/linux/alpha/kernel_stat.h   | 24 +++---
 sysdeps/unix/sysv/linux/alpha/xstatconv.c     | 24 +++---
 3 files changed, 66 insertions(+), 63 deletions(-)

diff --git a/sysdeps/unix/sysv/linux/alpha/bits/struct_stat.h b/sysdeps/unix/sysv/linux/alpha/bits/struct_stat.h
index 1c9b4248b8..d2aae9fdd7 100644
--- a/sysdeps/unix/sysv/linux/alpha/bits/stat.h
+++ b/sysdeps/unix/sysv/linux/alpha/bits/stat.h
@@ -23,37 +23,6 @@
 #ifndef _BITS_STRUCT_STAT_H
 #define _BITS_STRUCT_STAT_H	1

-/* Nanosecond resolution timestamps are stored in a format equivalent to
-   'struct timespec'.  This is the type used whenever possible but the
-   Unix namespace rules do not allow the identifier 'timespec' to appear
-   in the <sys/stat.h> header.  Therefore we have to handle the use of
-   this header in strictly standard-compliant sources special.
-
-   Use neat tidy anonymous unions and structures when possible.  */
-
-#ifdef __USE_XOPEN2K8
-# if __GNUC_PREREQ(3,3)
-#  define __ST_TIME(X)				\
-	__extension__ union {			\
-	    struct timespec st_##X##tim;	\
-	    struct {				\
-		__time_t st_##X##time;		\
-		unsigned long st_##X##timensec;	\
-	    };					\
-	}
-# else
-#  define __ST_TIME(X) struct timespec st_##X##tim
-#  define st_atime st_atim.tv_sec
-#  define st_mtime st_mtim.tv_sec
-#  define st_ctime st_ctim.tv_sec
-# endif
-#else
-# define __ST_TIME(X)				\
-	__time_t st_##X##time;			\
-	unsigned long st_##X##timensec
-#endif
-
-
 struct stat
   {
     __dev_t st_dev;		/* Device.  */
@@ -77,9 +46,27 @@ struct stat
     __blksize_t st_blksize;	/* Optimal block size for I/O.  */
     __nlink_t st_nlink;		/* Link count.  */
     int __pad2;			/* Real padding.  */
-    __ST_TIME(a);		/* Time of last access.  */
-    __ST_TIME(m);		/* Time of last modification.  */
-    __ST_TIME(c);		/* Time of last status change.  */
+#ifdef __USE_XOPEN2K8
+    /* Nanosecond resolution timestamps are stored in a format
+       equivalent to 'struct timespec'.  This is the type used
+       whenever possible but the Unix namespace rules do not allow the
+       identifier 'timespec' to appear in the <sys/stat.h> header.
+       Therefore we have to handle the use of this header in strictly
+       standard-compliant sources special.  */
+    struct timespec st_atim;		/* Time of last access.  */
+    struct timespec st_mtim;		/* Time of last modification.  */
+    struct timespec st_ctim;		/* Time of last status change.  */
+# define st_atime st_atim.tv_sec	/* Backward compatibility.  */
+# define st_mtime st_mtim.tv_sec
+# define st_ctime st_ctim.tv_sec
+#else
+    __time_t st_atime;			/* Time of last access.  */
+    unsigned long int st_atimensec;	/* Nscecs of last access.  */
+    __time_t st_mtime;			/* Time of last modification.  */
+    unsigned long int st_mtimensec;	/* Nsecs of last modification.  */
+    __time_t st_ctime;			/* Time of last status change.  */
+    unsigned long int st_ctimensec;	/* Nsecs of last status change.  */
+#endif
     long __glibc_reserved[3];
   };

@@ -98,15 +85,31 @@ struct stat64
     __blksize_t st_blksize;	/* Optimal block size for I/O.  */
     __nlink_t st_nlink;		/* Link count.  */
     int __pad0;			/* Real padding.  */
-    __ST_TIME(a);		/* Time of last access.  */
-    __ST_TIME(m);		/* Time of last modification.  */
-    __ST_TIME(c);		/* Time of last status change.  */
+#ifdef __USE_XOPEN2K8
+    /* Nanosecond resolution timestamps are stored in a format
+       equivalent to 'struct timespec'.  This is the type used
+       whenever possible but the Unix namespace rules do not allow the
+       identifier 'timespec' to appear in the <sys/stat.h> header.
+       Therefore we have to handle the use of this header in strictly
+       standard-compliant sources special.  */
+    struct timespec st_atim;		/* Time of last access.  */
+    struct timespec st_mtim;		/* Time of last modification.  */
+    struct timespec st_ctim;		/* Time of last status change.  */
+# define st_atime st_atim.tv_sec	/* Backward compatibility.  */
+# define st_mtime st_mtim.tv_sec
+# define st_ctime st_ctim.tv_sec
+#else
+    __time_t st_atime;			/* Time of last access.  */
+    unsigned long int st_atimensec;	/* Nscecs of last access.  */
+    __time_t st_mtime;			/* Time of last modification.  */
+    unsigned long int st_mtimensec;	/* Nsecs of last modification.  */
+    __time_t st_ctime;			/* Time of last status change.  */
+    unsigned long int st_ctimensec;	/* Nsecs of last status change.  */
+#endif
     long __glibc_reserved[3];
   };
 #endif

-#undef __ST_TIME
-
 /* Tell code we have these members.  */
 #define	_STATBUF_ST_BLKSIZE
 #define _STATBUF_ST_RDEV
diff --git a/sysdeps/unix/sysv/linux/alpha/kernel_stat.h b/sysdeps/unix/sysv/linux/alpha/kernel_stat.h
index ff69045f8f..a292920969 100644
--- a/sysdeps/unix/sysv/linux/alpha/kernel_stat.h
+++ b/sysdeps/unix/sysv/linux/alpha/kernel_stat.h
@@ -9,9 +9,9 @@ struct kernel_stat
     unsigned int st_gid;
     unsigned int st_rdev;
     long int st_size;
-    unsigned long int st_atime;
-    unsigned long int st_mtime;
-    unsigned long int st_ctime;
+    unsigned long int st_atime_sec;
+    unsigned long int st_mtime_sec;
+    unsigned long int st_ctime_sec;
     unsigned int st_blksize;
     int st_blocks;
     unsigned int st_flags;
@@ -34,11 +34,11 @@ struct kernel_stat64
     unsigned int    st_nlink;
     unsigned int    __pad0;

-    unsigned long   st_atime;
+    unsigned long   st_atime_sec;
     unsigned long   st_atimensec;
-    unsigned long   st_mtime;
+    unsigned long   st_mtime_sec;
     unsigned long   st_mtimensec;
-    unsigned long   st_ctime;
+    unsigned long   st_ctime_sec;
     unsigned long   st_ctimensec;
     long            __glibc_reserved[3];
   };
@@ -54,9 +54,9 @@ struct glibc2_stat
     __gid_t st_gid;
     __dev_t st_rdev;
     __off_t st_size;
-    __time_t st_atime;
-    __time_t st_mtime;
-    __time_t st_ctime;
+    __time_t st_atime_sec;
+    __time_t st_mtime_sec;
+    __time_t st_ctime_sec;
     unsigned int st_blksize;
     int st_blocks;
     unsigned int st_flags;
@@ -74,9 +74,9 @@ struct glibc21_stat
     __gid_t st_gid;
     __dev_t st_rdev;
     __off_t st_size;
-    __time_t st_atime;
-    __time_t st_mtime;
-    __time_t st_ctime;
+    __time_t st_atime_sec;
+    __time_t st_mtime_sec;
+    __time_t st_ctime_sec;
     __blkcnt64_t st_blocks;
     __blksize_t st_blksize;
     unsigned int st_flags;
diff --git a/sysdeps/unix/sysv/linux/alpha/xstatconv.c b/sysdeps/unix/sysv/linux/alpha/xstatconv.c
index f716a10f34..43224a7f25 100644
--- a/sysdeps/unix/sysv/linux/alpha/xstatconv.c
+++ b/sysdeps/unix/sysv/linux/alpha/xstatconv.c
@@ -44,9 +44,9 @@ __xstat_conv (int vers, struct kernel_stat *kbuf, void *ubuf)
 	buf->st_gid = kbuf->st_gid;
 	buf->st_rdev = kbuf->st_rdev;
 	buf->st_size = kbuf->st_size;
-	buf->st_atime = kbuf->st_atime;
-	buf->st_mtime = kbuf->st_mtime;
-	buf->st_ctime = kbuf->st_ctime;
+	buf->st_atime_sec = kbuf->st_atime_sec;
+	buf->st_mtime_sec = kbuf->st_mtime_sec;
+	buf->st_ctime_sec = kbuf->st_ctime_sec;
 	buf->st_blksize = kbuf->st_blksize;
 	buf->st_blocks = kbuf->st_blocks;
 	buf->st_flags = kbuf->st_flags;
@@ -66,9 +66,9 @@ __xstat_conv (int vers, struct kernel_stat *kbuf, void *ubuf)
 	buf->st_gid = kbuf->st_gid;
 	buf->st_rdev = kbuf->st_rdev;
 	buf->st_size = kbuf->st_size;
-	buf->st_atime = kbuf->st_atime;
-	buf->st_mtime = kbuf->st_mtime;
-	buf->st_ctime = kbuf->st_ctime;
+	buf->st_atime_sec = kbuf->st_atime_sec;
+	buf->st_mtime_sec = kbuf->st_mtime_sec;
+	buf->st_ctime_sec = kbuf->st_ctime_sec;
 	buf->st_blocks = kbuf->st_blocks;
 	buf->st_blksize = kbuf->st_blksize;
 	buf->st_flags = kbuf->st_flags;
@@ -98,12 +98,12 @@ __xstat_conv (int vers, struct kernel_stat *kbuf, void *ubuf)
 	buf->st_nlink = kbuf->st_nlink;
 	buf->__pad0 = 0;

-	buf->st_atime = kbuf->st_atime;
-	buf->st_atimensec = 0;
-	buf->st_mtime = kbuf->st_mtime;
-	buf->st_mtimensec = 0;
-	buf->st_ctime = kbuf->st_ctime;
-	buf->st_ctimensec = 0;
+	buf->st_atim.tv_sec = kbuf->st_atime_sec;
+	buf->st_atim.tv_nsec = 0;
+	buf->st_mtim.tv_sec = kbuf->st_mtime_sec;
+	buf->st_mtim.tv_nsec = 0;
+	buf->st_ctim.tv_sec = kbuf->st_ctime_sec;
+	buf->st_ctim.tv_nsec = 0;

 	buf->__glibc_reserved[0] = 0;
 	buf->__glibc_reserved[1] = 0;
EOF
	fi
}

add_automatic gmp

builddep_gnu_efi() {
	# binutils dependency needs cross translation
	apt_get_install debhelper
}

add_automatic gnupg2
add_automatic gpm
add_automatic grep
add_automatic groff

add_automatic guile-2.2
patch_guile_2_2() {
	if dpkg-architecture "-a$HOST_ARCH" -imusl-linux-any; then
		echo "fixing generation of charset.alias for musl #990250"
		drop_privs patch -p1 <<'EOF'
--- a/lib/Makefile.am
+++ b/lib/Makefile.am
@@ -1043,7 +1043,7 @@ install-exec-localcharset: all-local
 	  case '$(host_os)' in \
 	    darwin[56]*) \
 	      need_charset_alias=true ;; \
-	    darwin* | cygwin* | mingw* | pw32* | cegcc*) \
+	    darwin* | cygwin* | mingw* | pw32* | cegcc* | linux-musl*) \
 	      need_charset_alias=false ;; \
 	    *) \
 	      need_charset_alias=true ;; \
EOF
	fi
}

add_automatic guile-3.0
patch_guile_3_0() {
	if dpkg-architecture "-a$HOST_ARCH" -imusl-linux-any; then
		echo "fixing generation of charset.alias for musl #990514"
		drop_privs patch -p1 <<'EOF'
--- a/lib/Makefile.am
+++ b/lib/Makefile.am
@@ -1043,7 +1043,7 @@ install-exec-localcharset: all-local
 	  case '$(host_os)' in \
 	    darwin[56]*) \
 	      need_charset_alias=true ;; \
-	    darwin* | cygwin* | mingw* | pw32* | cegcc*) \
+	    darwin* | cygwin* | mingw* | pw32* | cegcc* | linux-musl*) \
 	      need_charset_alias=false ;; \
 	    *) \
 	      need_charset_alias=true ;; \
EOF
	fi
}

add_automatic gzip
buildenv_gzip() {
	if test "$LIBC_NAME" = musl; then
		# this avoids replacing fseeko with a variant that is broken
		echo gl_cv_func_fflush_stdin exported
		export gl_cv_func_fflush_stdin=yes
	fi
	if test "$(dpkg-architecture "-a$1" -qDEB_HOST_ARCH_BITS)" = 32; then
		# If touch works with large timestamps (e.g. on amd64),
		# gzip fails instead of warning about 32bit time_t.
		echo "TIME_T_32_BIT_OK=yes exported"
		export TIME_T_32_BIT_OK=yes
	fi
}

add_automatic hostname
add_automatic icu
add_automatic isl-0.18
add_automatic jansson
add_automatic jemalloc
add_automatic keyutils
add_automatic kmod

add_automatic krb5
buildenv_krb5() {
	export krb5_cv_attr_constructor_destructor=yes,yes
	export ac_cv_func_regcomp=yes
	export ac_cv_printf_positional=yes
}

add_automatic libassuan
add_automatic libatomic-ops
add_automatic libbsd
add_automatic libcap2
add_automatic libdebian-installer
add_automatic libev
add_automatic libevent

add_automatic libffi
patch_libffi() {
	if test "$HOST_ARCH" = musl-linux-mipsel; then
		echo "fixing symbols #989158"
		drop_privs sed -i -e 's/mipsel/any-mipsel/' debian/libffi7.symbols
	fi
	if test "$HOST_ARCH" = musl-linux-mips; then
		echo "fixing symbols #990257"
		drop_privs sed -i -e 's/ !\(mips \)/ !any-\1/' debian/libffi7.symbols
	fi
}

add_automatic libgc
patch_libgc() {
	if test "$HOST_ARCH" = mips64; then
		echo "updating libgc1 symbols for mips64 #990701"
		drop_privs sed -i -e 's/!mips64el/!mips64 &/' debian/libgc1.symbols
	fi
	if test "$HOST_ARCH" = nios2; then
		echo "enabling atomic builtins for nios2 #991294"
		drop_privs patch -p1 <<'EOF'
--- a/debian/libgc1.symbols
+++ b/debian/libgc1.symbols
@@ -4,8 +4,8 @@
  (arch=kfreebsd-amd64 kfreebsd-i386)GC_FreeBSDGetDataStart@Base 1:7.2d
  (arch=sparc sparc64)GC_SysVGetDataStart@Base 1:7.2d
  GC_abort_on_oom@Base 1:8.0
- (arch=!nios2 !sh4)GC_acquire_mark_lock@Base 1:8.0
- (arch=!nios2 !sh4)GC_active_count@Base 1:8.0
+ (arch=!sh4)GC_acquire_mark_lock@Base 1:8.0
+ (arch=!sh4)GC_active_count@Base 1:8.0
  GC_add_ext_descriptor@Base 1:7.2d
  GC_add_map_entry@Base 1:7.2d
  GC_add_roots@Base 1:7.2d
@@ -53,7 +53,7 @@
  GC_build_fl@Base 1:7.2d
  GC_build_fl_clear2@Base 1:7.2d
  GC_build_fl_clear4@Base 1:7.2d
- (arch=!nios2 !sh4)GC_bytes_allocd_tmp@Base 1:8.0
+ (arch=!sh4)GC_bytes_allocd_tmp@Base 1:8.0
  GC_bytes_found@Base 1:7.2d
  GC_call_with_alloc_lock@Base 1:7.2d
  GC_call_with_gc_active@Base 1:7.2d
@@ -146,8 +146,8 @@
  GC_do_blocking@Base 1:7.2d
  GC_do_blocking_inner@Base 1:7.2d
  GC_do_enumerate_reachable_objects@Base 1:7.6.4
- (arch=!nios2 !sh4)GC_do_local_mark@Base 1:8.0
- (arch=!nios2 !sh4)GC_do_parallel_mark@Base 1:8.0
+ (arch=!sh4)GC_do_local_mark@Base 1:8.0
+ (arch=!sh4)GC_do_parallel_mark@Base 1:8.0
  GC_dont_expand@Base 1:7.2d
  GC_dont_gc@Base 1:7.2d
  GC_dont_precollect@Base 1:7.2d
@@ -194,8 +194,8 @@
  (arch=!arm64 !nios2 !mips !mips64el !mipsel !riscv64 !s390 !s390x)GC_find_limit_with_bound@Base 1:7.2d
  GC_findleak_delay_free@Base 1:7.2d
  GC_finish_collection@Base 1:7.2d
- (arch=!nios2 !sh4)GC_first_nonempty@Base 1:8.0
- (arch=!nios2 !sh4)GC_fl_builder_count@Base 1:8.0
+ (arch=!sh4)GC_first_nonempty@Base 1:8.0
+ (arch=!sh4)GC_fl_builder_count@Base 1:8.0
  GC_fnlz_roots@Base 1:7.6.4
  GC_fo_entries@Base 1:7.2d
  GC_force_unmap_on_gcollect@Base 1:7.2d
@@ -295,9 +295,9 @@
  GC_hblkfreelist@Base 1:7.2d
  GC_header_cache_miss@Base 1:7.2d
  GC_heapsize_at_forced_unmap@Base 1:7.6.4
- (arch=!nios2 !sh4)GC_help_marker@Base 1:8.0
- (arch=!nios2 !sh4)GC_help_wanted@Base 1:8.0
- (arch=!nios2 !sh4)GC_helper_count@Base 1:8.0
+ (arch=!sh4)GC_help_marker@Base 1:8.0
+ (arch=!sh4)GC_help_wanted@Base 1:8.0
+ (arch=!sh4)GC_helper_count@Base 1:8.0
  GC_ignore_self_finalize_mark_proc@Base 1:7.2d
  GC_ignore_warn_proc@Base 1:7.2d
  GC_in_thread_creation@Base 1:7.2d
@@ -372,16 +372,16 @@
  GC_mark_and_push_stack@Base 1:7.2d
  GC_mark_from@Base 1:7.2d
  GC_mark_init@Base 1:7.2d
- (arch=!nios2 !sh4)GC_mark_local@Base 1:8.0
- (arch=!nios2 !sh4)GC_mark_no@Base 1:8.0
+ (arch=!sh4)GC_mark_local@Base 1:8.0
+ (arch=!sh4)GC_mark_no@Base 1:8.0
  GC_mark_some@Base 1:7.2d
  GC_mark_stack_size@Base 1:7.2d
  GC_mark_stack_too_small@Base 1:7.2d
  GC_mark_state@Base 1:7.2d
- (arch=!nios2 !sh4)GC_mark_thread@Base 1:8.0
+ (arch=!sh4)GC_mark_thread@Base 1:8.0
  GC_mark_thread_local_fls_for@Base 1:8.0
  GC_mark_thread_local_free_lists@Base 1:8.0
- (arch=!nios2 !sh4)GC_mark_threads@Base 1:8.0
+ (arch=!sh4)GC_mark_threads@Base 1:8.0
  GC_mark_togglerefs@Base 1:7.6.4
  GC_max_heapsize@Base 1:7.4.2
  GC_max_retries@Base 1:7.2d
@@ -420,8 +420,8 @@
  GC_noop6@Base 1:7.4.2
  GC_noop_sink@Base 1:7.2d
  GC_normal_finalize_mark_proc@Base 1:7.2d
- (arch=!nios2 !sh4)GC_notify_all_builder@Base 1:8.0
- (arch=!nios2 !sh4)GC_notify_all_marker@Base 1:8.0
+ (arch=!sh4)GC_notify_all_builder@Base 1:8.0
+ (arch=!sh4)GC_notify_all_marker@Base 1:8.0
  GC_notify_or_invoke_finalizers@Base 1:7.2d
  GC_nprocs@Base 1:7.2d
  GC_null_finalize_mark_proc@Base 1:7.2d
@@ -493,9 +493,9 @@
  GC_push_current_stack@Base 1:7.2d
  GC_push_finalizer_structures@Base 1:7.2d
  GC_push_gc_structures@Base 1:7.2d
- (arch=nios2 sh4)GC_push_marked1@Base 1:7.4.2
- (arch=!alpha !amd64 !arm64 !armel !armhf !hppa !hurd-i386 !i386 !ia64 !kfreebsd-amd64 !kfreebsd-i386 !m68k !mips !mips64el !mipsel !powerpc !powerpcspe !ppc64 !ppc64el !riscv64 !s390x !sparc !sparc64 !x32)GC_push_marked2@Base 1:7.4.2
- (arch=!alpha !amd64 !arm64 !armel !armhf !hppa !hurd-i386 !i386 !ia64 !kfreebsd-amd64 !kfreebsd-i386 !m68k !mips !mips64el !mipsel !powerpc !powerpcspe !ppc64 !ppc64el !riscv64 !s390x !sparc !sparc64 !x32)GC_push_marked4@Base 1:7.4.2
+ (arch=sh4)GC_push_marked1@Base 1:7.4.2
+ (arch=!alpha !amd64 !arm64 !armel !armhf !hppa !hurd-i386 !i386 !ia64 !kfreebsd-amd64 !kfreebsd-i386 !m68k !mips !mips64el !mipsel !nios2 !powerpc !powerpcspe !ppc64 !ppc64el !riscv64 !s390x !sparc !sparc64 !x32)GC_push_marked2@Base 1:7.4.2
+ (arch=!alpha !amd64 !arm64 !armel !armhf !hppa !hurd-i386 !i386 !ia64 !kfreebsd-amd64 !kfreebsd-i386 !m68k !mips !mips64el !mipsel !nios2 !powerpc !powerpcspe !ppc64 !ppc64el !riscv64 !s390x !sparc !sparc64 !x32)GC_push_marked4@Base 1:7.4.2
  GC_push_marked@Base 1:7.2d
  GC_push_next_marked@Base 1:7.2d
  GC_push_next_marked_dirty@Base 1:7.2d
@@ -545,7 +545,7 @@
  GC_register_my_thread@Base 1:7.2d
  GC_register_my_thread_inner@Base 1:7.2d
  (arch=ia64)GC_register_stackbottom@Base 1:7.2d
- (arch=!nios2 !sh4)GC_release_mark_lock@Base 1:8.0
+ (arch=!sh4)GC_release_mark_lock@Base 1:8.0
  GC_remap@Base 1:8.0
  GC_remove_all_threads_but_me@Base 1:7.4.2
  GC_remove_allowed_signals@Base 1:7.2d
@@ -565,7 +565,7 @@
  GC_restart_handler@Base 1:7.2d
  (arch=!kfreebsd-amd64 !kfreebsd-i386)GC_resume_thread@Base 1:7.6.4
  GC_retry_signals@Base 1:7.2d
- (arch=!nios2 !sh4)GC_return_mark_stack@Base 1:8.0
+ (arch=!sh4)GC_return_mark_stack@Base 1:8.0
  GC_root_size@Base 1:7.2d
  GC_roots_present@Base 1:7.2d
  GC_same_obj@Base 1:7.2d
@@ -639,7 +639,7 @@
  GC_start_world_external@Base 1:8.0
  GC_stderr@Base 1:7.2d
  GC_stdout@Base 1:7.2d
- (arch=!nios2 !sh4)GC_steal_mark_stack@Base 1:8.0
+ (arch=!sh4)GC_steal_mark_stack@Base 1:8.0
  GC_stop_count@Base 1:7.2d
  GC_stop_init@Base 1:7.2d
  GC_stop_world@Base 1:7.2d
@@ -692,11 +692,11 @@
  GC_use_entire_heap@Base 1:7.2d
  GC_used_heap_size_after_full@Base 1:7.2d
  GC_version@Base 1:7.2d
- (arch=!nios2 !sh4)GC_wait_builder@Base 1:8.0
+ (arch=!sh4)GC_wait_builder@Base 1:8.0
  GC_wait_for_gc_completion@Base 1:7.2d
  (arch=!sh4)GC_wait_for_markers_init@Base 1:8.0
- (arch=!nios2 !sh4)GC_wait_for_reclaim@Base 1:8.0
- (arch=!nios2 !sh4)GC_wait_marker@Base 1:8.0
+ (arch=!sh4)GC_wait_for_reclaim@Base 1:8.0
+ (arch=!sh4)GC_wait_marker@Base 1:8.0
  GC_with_callee_saves_pushed@Base 1:7.2d
  GC_world_is_stopped@Base 1:7.2d
  GC_world_stopped@Base 1:8.0
--- a/debian/rules
+++ b/debian/rules
@@ -8,7 +8,7 @@
 LDFLAGS += -pthread

 ifneq ($(DEB_BUILD_ARCH),$(DEB_HOST_ARCH))
-ATOMIC_BUILTIN_ARCHS = alpha amd64 arm64 armel armhf hppa hurd-i386 i386 ia64 kfreebsd-amd64 kfreebsd-i386 mips64el mipsel powerpc ppc64 ppc64el riscv64 s390x x32
+ATOMIC_BUILTIN_ARCHS = alpha amd64 arm64 armel armhf hppa hurd-i386 i386 ia64 kfreebsd-amd64 kfreebsd-i386 mips64el mipsel nios2 powerpc ppc64 ppc64el riscv64 s390x x32
 endif

 %:
EOF
	fi
}
buildenv_libgc() {
	if dpkg-architecture "-a$1" -imusl-linux-any; then
		echo "ignoring symbol differences for musl for now"
		export DPKG_GENSYMBOLS_CHECK_LEVEL=0
	fi
}

add_automatic libgcrypt20
buildenv_libgcrypt20() {
	export ac_cv_sys_symbol_underscore=no
}

add_automatic libgpg-error
add_automatic libice
add_automatic libidn
add_automatic libidn2
add_automatic libksba
add_automatic libmd
add_automatic libnsl
add_automatic libonig
add_automatic libpipeline
add_automatic libpng1.6

buildenv_libprelude() {
	case $(dpkg-architecture "-a$HOST_ARCH" -qDEB_HOST_GNU_SYSTEM) in *gnu*)
		echo "glibc does not return NULL for malloc(0)"
		export ac_cv_func_malloc_0_nonnull=yes
	;; esac
}

add_automatic libpsl
add_automatic libpthread-stubs

patch_libselinux() {
	if dpkg-architecture "-a$HOST_ARCH" -imusl-linux-any; then
		echo "fix ftbfs on musl #989748"
		drop_privs patch -p1 <<'EOF'
--- a/src/Makefile
+++ b/src/Makefile
@@ -98,6 +98,10 @@ override LDFLAGS += -L/opt/local/lib -un
 LD_SONAME_FLAGS=-install_name,$(LIBSO)
 endif

+ifeq (yes,$(shell printf '#define _GNU_SOURCE\n#include <unistd.h>\n#include <sys/types.h>\nint main(void){pid_t n=gettid();return n;}' | $(CC) -x c -o /dev/null - >/dev/null 2>&1 && echo yes))
+CFLAGS += -DHAVE_GETTID
+endif
+
 PCRE_LDLIBS ?= -lpcre
 # override with -lfts when building on Musl libc to use fts-standalone
 FTS_LDLIBS ?=
--- a/src/procattr.c
+++ b/src/procattr.c
@@ -22,19 +22,7 @@ static pthread_key_t destructor_key;
 static int destructor_key_initialized = 0;
 static __thread char destructor_initialized;

-/* Bionic and glibc >= 2.30 declare gettid() system call wrapper in unistd.h and
- * has a definition for it */
-#ifdef __BIONIC__
-  #define OVERRIDE_GETTID 0
-#elif !defined(__GLIBC_PREREQ)
-  #define OVERRIDE_GETTID 1
-#elif !__GLIBC_PREREQ(2,30)
-  #define OVERRIDE_GETTID 1
-#else
-  #define OVERRIDE_GETTID 0
-#endif
-
-#if OVERRIDE_GETTID
+#ifndef HAVE_GETTID
 static pid_t gettid(void)
 {
 	return syscall(__NR_gettid);
EOF
	fi
}

add_automatic libsepol
add_automatic libsm
add_automatic libsodium

add_automatic libssh2
add_automatic libssh2
patch_libssh2() {
	echo "fix FTBFS #993176"
	drop_privs sed -i -e '/m4_undefine..backend/d' configure.ac
}

add_automatic libsystemd-dummy

add_automatic libtasn1-6
builddep_libtasn1_6() {
	echo "working around FTBFS #992928"
	apt_get_install gtk-doc-tools
	apt_get_build_dep "-a$1" --arch-only -P "$2" ./
}

add_automatic libtextwrap
add_automatic libtirpc

builddep_libtool() {
	assert_built "zlib"
	test "$1" = "$HOST_ARCH"
	# gfortran dependency needs cross-translation
	# gnulib dependency lacks M-A:foreign
	apt_get_install debhelper file "gfortran-$GCC_VER$HOST_ARCH_SUFFIX" automake autoconf autotools-dev help2man texinfo "zlib1g-dev:$HOST_ARCH" gnulib
}

add_automatic libunistring
buildenv_libunistring() {
	if dpkg-architecture "-a$HOST_ARCH" -ignu-any-any; then
		echo "glibc does not prefer rwlock writers to readers"
		export gl_cv_pthread_rwlock_rdlock_prefer_writer=no
	fi
}

add_automatic libusb
add_automatic libusb-1.0
add_automatic libverto

add_automatic libx11
buildenv_libx11() {
	export xorg_cv_malloc0_returns_null=no
}

add_automatic libxau
add_automatic libxaw
add_automatic libxcb
add_automatic libxdmcp

add_automatic libxext
buildenv_libxext() {
	export xorg_cv_malloc0_returns_null=no
}

add_automatic libxmu
add_automatic libxpm

add_automatic libxrender
buildenv_libxrender() {
	export xorg_cv_malloc0_returns_null=no
}

add_automatic libxss
buildenv_libxss() {
	export xorg_cv_malloc0_returns_null=no
}

add_automatic libxt
buildenv_libxt() {
	export xorg_cv_malloc0_returns_null=no
}

add_automatic libzstd

patch_linux() {
	local kernel_arch comment
	kernel_arch=
	comment="just building headers yet"
	case "$HOST_ARCH" in
		arc|csky|ia64|nios2)
			kernel_arch=$HOST_ARCH
		;;
		mipsr6|mipsr6el|mipsn32r6|mipsn32r6el|mips64r6|mips64r6el)
			kernel_arch=defines-only
		;;
		powerpcel) kernel_arch=powerpc; ;;
		riscv64) kernel_arch=riscv; ;;
		*-linux-*)
			if ! test -d "debian/config/$HOST_ARCH"; then
				kernel_arch=$(sed 's/^kernel-arch: //;t;d' < "debian/config/${HOST_ARCH#*-linux-}/defines")
				comment="$HOST_ARCH must be part of a multiarch installation with a ${HOST_ARCH#*-linux-*} kernel"
			fi
		;;
	esac
	if test -n "$kernel_arch"; then
		if test "$kernel_arch" != defines-only; then
			echo "patching linux for $HOST_ARCH with kernel-arch $kernel_arch"
			drop_privs mkdir -p "debian/config/$HOST_ARCH"
			drop_privs tee "debian/config/$HOST_ARCH/defines" >/dev/null <<EOF
[base]
kernel-arch: $kernel_arch
featuresets:
# empty; $comment
EOF
		else
			echo "patching linux to enable $HOST_ARCH"
		fi
		drop_privs sed -i -e "/^arches:/a\\ $HOST_ARCH" debian/config/defines
		apt_get_install kernel-wedge
		drop_privs ./debian/rules debian/rules.gen || : # intentionally exits 1 to avoid being called automatically. we are doing it wrong
	fi
}

add_automatic lz4
add_automatic make-dfsg
add_automatic man-db
add_automatic mawk
add_automatic mpclib3
add_automatic mpdecimal

add_automatic mpfr4
patch_mpfr4() {
	if test "$HOST_ARCH" = musl-linux-arm64; then
		echo "fixing symbols for musl-linux-arm64 #988008"
		drop_privs sed -i -e '/^ /s/arm64/any-&/' debian/libmpfr6.symbols
	fi
	if test "$HOST_ARCH" = musl-linux-armhf; then
		echo "fixing symbols for musl-linux-armhf #988760"
		drop_privs sed -i -e '/^ /s/armhf/eabihf-any-any-arm/' debian/libmpfr6.symbols
	fi
}

builddep_ncurses() {
	if test "$(dpkg-architecture "-a$HOST_ARCH" -qDEB_HOST_ARCH_OS)" = linux; then
		assert_built gpm
		apt_get_install "libgpm-dev:$1"
	fi
	# g++-multilib dependency unsatisfiable
	apt_get_install debhelper pkg-config autoconf-dickey
	case "$ENABLE_MULTILIB:$HOST_ARCH" in
		yes:amd64|yes:i386|yes:powerpc|yes:ppc64|yes:s390|yes:sparc)
			test "$1" = "$HOST_ARCH"
			apt_get_install "g++-$GCC_VER-multilib$HOST_ARCH_SUFFIX"
			# the unversioned gcc-multilib$HOST_ARCH_SUFFIX should contain the following link
			ln -sf "`dpkg-architecture -a$HOST_ARCH -qDEB_HOST_MULTIARCH`/asm" /usr/include/asm
		;;
	esac
}

add_automatic nettle
add_automatic nghttp2
add_automatic npth
add_automatic nspr

add_automatic nss
patch_nss() {
	if dpkg-architecture "-a$HOST_ARCH" -iany-ppc64el; then
		echo "fix FTCBFS for ppc64el #948523"
		drop_privs patch -p1 <<'EOF'
--- a/debian/rules
+++ b/debian/rules
@@ -40,7 +40,8 @@
 ifeq ($(origin RANLIB),default)
 TOOLCHAIN += RANLIB=$(DEB_HOST_GNU_TYPE)-ranlib
 endif
-TOOLCHAIN += OS_TEST=$(DEB_HOST_GNU_CPU)
+OS_TYPE_map_powerpc64le = ppc64le
+TOOLCHAIN += OS_TEST=$(or $(OS_TYPE_map_$(DEB_HOST_GNU_CPU)),$(DEB_HOST_GNU_CPU))
 TOOLCHAIN += KERNEL=$(DEB_HOST_ARCH_OS)
 endif

EOF
	fi
	echo "work around FTBFS #984258"
	drop_privs patch -p1 <<'EOF'
--- a/debian/rules
+++ b/debian/rules
@@ -110,6 +110,7 @@
 		NSPR_LIB_DIR=/usr/lib/$(DEB_HOST_MULTIARCH) \
 		BUILD_OPT=1 \
 		NS_USE_GCC=1 \
+		NSS_ENABLE_WERROR=0 \
 		OPTIMIZER="$(CFLAGS) $(CPPFLAGS)" \
 		LDFLAGS='$(LDFLAGS) $$(ARCHFLAG) $$(ZDEFS_FLAG)' \
 		DSO_LDOPTS='-shared $$(LDFLAGS)' \
EOF
}

buildenv_openldap() {
	export ol_cv_pthread_select_yields=yes
	export ac_cv_func_memcmp_working=yes
}

add_automatic openssl
add_automatic openssl1.0

add_automatic p11-kit
patch_p11_kit() {
	dpkg-architecture "-a$HOST_ARCH" -ihurd-any || return 0
	echo "addressing FTBFS on hurd-any #989235"
	drop_privs patch -p1 <<'EOF'
--- a/p11-kit/lists.c
+++ b/p11-kit/lists.c
@@ -40,6 +40,7 @@
 #include <assert.h>
 #include <ctype.h>
 #include <string.h>
+#include <stdint.h>
 #include <stdio.h>
 #include <stdlib.h>
 #include <unistd.h>
EOF
}

add_automatic patch

add_automatic pcre2
patch_pcre2() {
	if dpkg-architecture "-a$HOST_ARCH" -imusl-linux-any; then
		echo "fixing libc dependency #989729"
		drop_privs sed -i -e s/libc6-dev/libc-dev/ debian/control
	fi
}

add_automatic pcre3
add_automatic popt

builddep_readline() {
	assert_built "ncurses"
	# gcc-multilib dependency unsatisfiable
	apt_get_install debhelper "libtinfo-dev:$1" "libncursesw5-dev:$1" mawk texinfo autotools-dev
	case "$ENABLE_MULTILIB:$HOST_ARCH" in
		yes:amd64|yes:ppc64)
			test "$1" = "$HOST_ARCH"
			apt_get_install "gcc-$GCC_VER-multilib$HOST_ARCH_SUFFIX" "lib32tinfo-dev:$1" "lib32ncursesw5-dev:$1"
			# the unversioned gcc-multilib$HOST_ARCH_SUFFIX should contain the following link
			ln -sf "`dpkg-architecture -a$1 -qDEB_HOST_MULTIARCH`/asm" /usr/include/asm
		;;
		yes:i386|yes:powerpc|yes:sparc|yes:s390)
			test "$1" = "$HOST_ARCH"
			apt_get_install "gcc-$GCC_VER-multilib$HOST_ARCH_SUFFIX" "lib64ncurses5-dev:$1"
			# the unversioned gcc-multilib$HOST_ARCH_SUFFIX should contain the following link
			ln -sf "`dpkg-architecture -a$1 -qDEB_HOST_MULTIARCH`/asm" /usr/include/asm
		;;
	esac
}
patch_readline() {
	echo "patching readline to support nobiarch profile #737955"
	drop_privs patch -p1 <<'EOF'
--- a/debian/control
+++ b/debian/control
@@ -5,9 +5,9 @@
 Standards-Version: 4.5.0
 Build-Depends: debhelper (>= 11),
   libncurses-dev,
-  lib32ncurses-dev [amd64 ppc64], lib64ncurses-dev [i386 powerpc sparc s390],
+  lib32ncurses-dev [amd64 ppc64] <!nobiarch>, lib64ncurses-dev [i386 powerpc sparc s390] <!nobiarch>,
   mawk | awk, texinfo,
-  gcc-multilib [amd64 i386 kfreebsd-amd64 powerpc ppc64 s390 sparc]
+  gcc-multilib [amd64 i386 kfreebsd-amd64 powerpc ppc64 s390 sparc] <!nobiarch>

 Package: libreadline8
 Architecture: any
@@ -27,6 +27,7 @@
 Architecture: i386 powerpc s390 sparc
 Depends: readline-common, ${shlibs:Depends}, ${misc:Depends}
 Section: libs
+Build-Profiles: <!nobiarch>
 Description: GNU readline and history libraries, run-time libraries (64-bit)
  The GNU readline library aids in the consistency of user interface
  across discrete programs that need to provide a command line
@@ -75,6 +76,7 @@
 Conflicts: lib64readline6-dev, lib64readline-gplv2-dev
 Provides: lib64readline6-dev
 Section: libdevel
+Build-Profiles: <!nobiarch>
 Description: GNU readline and history libraries, development files (64-bit)
  The GNU readline library aids in the consistency of user interface
  across discrete programs that need to provide a command line
@@ -101,6 +103,7 @@
 Architecture: amd64 ppc64
 Depends: readline-common, ${shlibs:Depends}, ${misc:Depends}
 Section: libs
+Build-Profiles: <!nobiarch>
 Description: GNU readline and history libraries, run-time libraries (32-bit)
  The GNU readline library aids in the consistency of user interface
  across discrete programs that need to provide a command line
@@ -115,6 +118,7 @@
 Conflicts: lib32readline6-dev, lib32readline-gplv2-dev
 Provides: lib32readline6-dev
 Section: libdevel
+Build-Profiles: <!nobiarch>
 Description: GNU readline and history libraries, development files (32-bit)
  The GNU readline library aids in the consistency of user interface
  across discrete programs that need to provide a command line
--- a/debian/rules
+++ b/debian/rules
@@ -57,6 +57,11 @@
   endif
 endif

+ifneq (,$(filter nobiarch,$(DEB_BUILD_PROFILES)))
+build32 =
+build64 =
+endif
+
 unexport CPPFLAGS CFLAGS LDFLAGS

 CFLAGS := $(shell dpkg-buildflags --get CFLAGS)
EOF
}

add_automatic rtmpdump
add_automatic sed
add_automatic shadow
add_automatic slang2
add_automatic spdylay
add_automatic sqlite3
add_automatic sysvinit

add_automatic tar
buildenv_tar() {
	case $(dpkg-architecture "-a$HOST_ARCH" -qDEB_HOST_GNU_SYSTEM) in *gnu*)
		echo "struct dirent contains working d_ino on glibc systems"
		export gl_cv_struct_dirent_d_ino=yes
	;; esac
	if ! dpkg-architecture "-a$HOST_ARCH" -ilinux-any; then
		echo "forcing broken posix acl check to fail on non-linux #850668"
		export gl_cv_getxattr_with_posix_acls=no
	fi
}

add_automatic tcl8.6
buildenv_tcl8_6() {
	export tcl_cv_strtod_buggy=ok
	export tcl_cv_strtoul_unbroken=ok
}

add_automatic tcltk-defaults
add_automatic tcp-wrappers

add_automatic tk8.6
buildenv_tk8_6() {
	export tcl_cv_strtod_buggy=ok
}

add_automatic uchardet
add_automatic ustr

buildenv_util_linux() {
	export scanf_cv_type_modifier=ms
}

add_automatic xft
add_automatic xxhash

add_automatic xz-utils
buildenv_xz_utils() {
	if dpkg-architecture "-a$1" -imusl-linux-any; then
		echo "ignoring symbol differences for musl for now"
		export DPKG_GENSYMBOLS_CHECK_LEVEL=0
	fi
}

builddep_zlib() {
	# gcc-multilib dependency unsatisfiable
	apt_get_install debhelper binutils dpkg-dev
}

# choosing libatomic1 arbitrarily here, cause it never bumped soname
BUILD_GCC_MULTIARCH_VER=`apt-cache show --no-all-versions libatomic1 | sed 's/^Source: gcc-\([0-9.]*\)$/\1/;t;d'`
if test "$GCC_VER" != "$BUILD_GCC_MULTIARCH_VER"; then
	echo "host gcc version ($GCC_VER) and build gcc version ($BUILD_GCC_MULTIARCH_VER) mismatch. need different build gcc"
if dpkg --compare-versions "$GCC_VER" gt "$BUILD_GCC_MULTIARCH_VER"; then
	echo "deb [ arch=$(dpkg --print-architecture) ] $MIRROR experimental main" > /etc/apt/sources.list.d/tmp-experimental.list
	$APT_GET update
	$APT_GET -t experimental install g++ g++-$GCC_VER
	test "$GCC_VER" = 11 && $APT_GET -t experimental install binutils
	rm -f /etc/apt/sources.list.d/tmp-experimental.list
	$APT_GET update
elif test -f "$REPODIR/stamps/gcc_0"; then
	echo "skipping rebuild of build gcc"
	$APT_GET --force-yes dist-upgrade # downgrade!
else
	cross_build_setup "gcc-$GCC_VER" gcc0
	apt_get_build_dep --arch-only ./
	# dependencies for common libs no longer declared
	apt_get_install doxygen graphviz ghostscript texlive-latex-base xsltproc docbook-xsl-ns
	(
		export gcc_cv_libc_provides_ssp=yes
		nolang=$(set_add "${GCC_NOLANG:-}" biarch)
		export DEB_BUILD_OPTIONS="$DEB_BUILD_OPTIONS nostrap nolang=$(join_words , $nolang)"
		drop_privs_exec dpkg-buildpackage -B -uc -us
	)
	cd ..
	ls -l
	reprepro include rebootstrap-native ./*.changes
	drop_privs rm -fv ./*-plugin-dev_*.deb ./*-dbg_*.deb
	dpkg -i *.deb
	touch "$REPODIR/stamps/gcc_0"
	cd ..
	drop_privs rm -Rf gcc0
fi
progress_mark "build compiler complete"
else
echo "host gcc version and build gcc version match. good for multiarch"
fi

if test -f "$REPODIR/stamps/cross-binutils"; then
	echo "skipping rebuild of binutils-target"
else
	cross_build_setup binutils
	check_binNMU
	apt_get_build_dep --arch-only -Pnocheck ./
	drop_privs TARGET=$HOST_ARCH dpkg-buildpackage -B -Pnocheck --target=stamps/control
	drop_privs TARGET=$HOST_ARCH dpkg-buildpackage -B -uc -us -Pnocheck
	cd ..
	ls -l
	pickup_packages *.changes
	apt_get_install "binutils$HOST_ARCH_SUFFIX"
	assembler="`dpkg-architecture -a$HOST_ARCH -qDEB_HOST_GNU_TYPE`-as"
	if ! which "$assembler"; then echo "$assembler missing in binutils package"; exit 1; fi
	if ! drop_privs "$assembler" -o test.o /dev/null; then echo "binutils fail to execute"; exit 1; fi
	if ! test -f test.o; then echo "binutils fail to create object"; exit 1; fi
	check_arch test.o "$HOST_ARCH"
	touch "$REPODIR/stamps/cross-binutils"
	cd ..
	drop_privs rm -Rf binutils
fi
progress_mark "cross binutils"

if test "$HOST_ARCH" = hppa && ! test -f "$REPODIR/stamps/cross-binutils-hppa64"; then
	cross_build_setup binutils binutils-hppa64
	check_binNMU
	apt_get_build_dep --arch-only -Pnocheck ./
	drop_privs with_hppa64=yes DEB_BUILD_OPTIONS="$DEB_BUILD_OPTIONS nocross nomult nopgo" dpkg-buildpackage -B -Pnocheck --target=stamps/control
	drop_privs with_hppa64=yes DEB_BUILD_OPTIONS="$DEB_BUILD_OPTIONS nocross nomult nopgo" dpkg-buildpackage -B -uc -us -Pnocheck
	cd ..
	ls -l
	pickup_additional_packages binutils-hppa64-linux-gnu_*.deb
	apt_get_install binutils-hppa64-linux-gnu
	if ! which hppa64-linux-gnu-as; then echo "hppa64-linux-gnu-as missing in binutils package"; exit 1; fi
	if ! drop_privs hppa64-linux-gnu-as -o test.o /dev/null; then echo "binutils-hppa64 fail to execute"; exit 1; fi
	if ! test -f test.o; then echo "binutils-hppa64 fail to create object"; exit 1; fi
	check_arch test.o hppa64
	touch "$REPODIR/stamps/cross-binutils-hppa64"
	cd ..
	drop_privs rm -Rf binutils-hppa64-linux-gnu
	progress_mark "cross binutils-hppa64"
fi

if test "`dpkg-architecture "-a$HOST_ARCH" -qDEB_HOST_ARCH_OS`" = "linux"; then
if test -f "$REPODIR/stamps/linux_1"; then
	echo "skipping rebuild of linux-libc-dev"
else
	cross_build_setup linux
	check_binNMU
	if dpkg-architecture -ilinux-any && test "$(dpkg-query -W -f '${Version}' "linux-libc-dev:$(dpkg --print-architecture)")" != "$(dpkg-parsechangelog -SVersion)"; then
		echo "rebootstrap-warning: working around linux-libc-dev m-a:same skew"
		apt_get_build_dep --arch-only -Pstage1 ./
		drop_privs KBUILD_VERBOSE=1 dpkg-buildpackage -B -Pstage1 -uc -us
	fi
	apt_get_build_dep --arch-only "-a$HOST_ARCH" -Pstage1 ./
	drop_privs KBUILD_VERBOSE=1 dpkg-buildpackage -B "-a$HOST_ARCH" -Pstage1 -uc -us
	cd ..
	ls -l
	if test "$ENABLE_MULTIARCH_GCC" != yes; then
		drop_privs dpkg-cross -M -a "$HOST_ARCH" -b ./*"_$HOST_ARCH.deb"
	fi
	pickup_packages *.deb
	touch "$REPODIR/stamps/linux_1"
	compare_native ./*.deb
	cd ..
	drop_privs rm -Rf linux
fi
progress_mark "linux-libc-dev cross build"
fi

if test "$(dpkg-architecture "-a$HOST_ARCH" -qDEB_HOST_ARCH_OS)" = hurd; then
if test -f "$REPODIR/stamps/gnumach_1"; then
	echo "skipping rebuild of gnumach stage1"
else
	cross_build_setup gnumach gnumach_1
	apt_get_build_dep "-a$HOST_ARCH" --arch-only -Pstage1 ./
	drop_privs dpkg-buildpackage -B "-a$HOST_ARCH" -Pstage1 -uc -us
	cd ..
	pickup_packages ./*.deb
	touch "$REPODIR/stamps/gnumach_1"
	cd ..
	drop_privs rm -Rf gnumach_1
fi
progress_mark "gnumach stage1 cross build"
fi

GCC_AUTOCONF=autoconf2.69

if test -f "$REPODIR/stamps/gcc_1"; then
	echo "skipping rebuild of gcc stage1"
else
	apt_get_install debhelper gawk patchutils bison flex lsb-release quilt libtool $GCC_AUTOCONF zlib1g-dev libmpc-dev libmpfr-dev libgmp-dev autogen systemtap-sdt-dev sharutils "binutils$HOST_ARCH_SUFFIX" time
	if test "$(dpkg-architecture "-a$HOST_ARCH" -qDEB_HOST_ARCH_OS)" = linux; then
		if test "$ENABLE_MULTIARCH_GCC" = yes; then
			apt_get_install "linux-libc-dev:$HOST_ARCH"
		else
			apt_get_install "linux-libc-dev-${HOST_ARCH}-cross"
		fi
	fi
	if test "$HOST_ARCH" = hppa; then
		apt_get_install binutils-hppa64-linux-gnu
	fi
	cross_build_setup "gcc-$GCC_VER" gcc1
	check_binNMU
	dpkg-checkbuilddeps || : # tell unmet build depends
	echo "$HOST_ARCH" > debian/target
	(
		nolang=${GCC_NOLANG:-}
		test "$ENABLE_MULTILIB" = yes || nolang=$(set_add "$nolang" biarch)
		export DEB_STAGE=stage1
		export DEB_BUILD_OPTIONS="$DEB_BUILD_OPTIONS${nolang:+ nolang=$(join_words , $nolang)}"
		drop_privs dpkg-buildpackage -d -T control
		dpkg-checkbuilddeps || : # tell unmet build depends again after rewriting control
		drop_privs_exec dpkg-buildpackage -d -b -uc -us
	)
	cd ..
	ls -l
	pickup_packages *.changes
	apt_get_remove gcc-multilib
	if test "$ENABLE_MULTILIB" = yes && ls | grep -q multilib; then
		apt_get_install "gcc-$GCC_VER-multilib$HOST_ARCH_SUFFIX"
	else
		rm -vf ./*multilib*.deb
		apt_get_install "gcc-$GCC_VER$HOST_ARCH_SUFFIX"
	fi
	compiler="`dpkg-architecture "-a$HOST_ARCH" -qDEB_HOST_GNU_TYPE`-gcc-$GCC_VER"
	if ! which "$compiler"; then echo "$compiler missing in stage1 gcc package"; exit 1; fi
	if ! drop_privs "$compiler" -x c -c /dev/null -o test.o; then echo "stage1 gcc fails to execute"; exit 1; fi
	if ! test -f test.o; then echo "stage1 gcc fails to create binaries"; exit 1; fi
	check_arch test.o "$HOST_ARCH"
	touch "$REPODIR/stamps/gcc_1"
	cd ..
	drop_privs rm -Rf gcc1
fi
progress_mark "cross gcc stage1 build"

# replacement for cross-gcc-defaults
for prog in c++ cpp g++ gcc gcc-ar gcc-ranlib gfortran; do
	ln -fs "`dpkg-architecture "-a$HOST_ARCH" -qDEB_HOST_GNU_TYPE`-$prog-$GCC_VER" "/usr/bin/`dpkg-architecture "-a$HOST_ARCH" -qDEB_HOST_GNU_TYPE`-$prog"
done

if test "$(dpkg-architecture "-a$HOST_ARCH" -qDEB_HOST_ARCH_OS)" = hurd; then
if test -f "$REPODIR/stamps/hurd_1"; then
	echo "skipping rebuild of hurd stage1"
else
	cross_build_setup hurd hurd_1
	apt_get_build_dep "-a$HOST_ARCH" --arch-only -P stage1 ./
	drop_privs dpkg-buildpackage -B "-a$HOST_ARCH" -Pstage1 -uc -us
	cd ..
	ls -l
	pickup_packages *.changes
	touch "$REPODIR/stamps/hurd_1"
	cd ..
	drop_privs rm -Rf hurd_1
fi
progress_mark "hurd stage1 cross build"
fi

if test "$(dpkg-architecture "-a$HOST_ARCH" -qDEB_HOST_ARCH_OS)" = hurd; then
if test -f "$REPODIR/stamps/mig_1"; then
	echo "skipping rebuild of mig cross"
else
	cross_build_setup mig mig_1
	apt_get_install dpkg-dev debhelper dh-exec dh-autoreconf "gnumach-dev:$HOST_ARCH" flex libfl-dev bison
	drop_privs dpkg-buildpackage -d -B "--target-arch=$HOST_ARCH" -uc -us
	cd ..
	ls -l
	pickup_packages *.changes
	touch "$REPODIR/stamps/mig_1"
	cd ..
	drop_privs rm -Rf mig_1
fi
progress_mark "cross mig build"
fi

# we'll have to remove build arch multilibs to be able to install host arch multilibs
apt_get_remove $(dpkg-query -W "libc[0-9]*-*:$(dpkg --print-architecture)" | sed "s/\\s.*//;/:$(dpkg --print-architecture)/d")

if test -f "$REPODIR/stamps/${LIBC_NAME}_2"; then
	echo "skipping rebuild of $LIBC_NAME stage2"
else
	cross_build_setup "$LIBC_NAME" "${LIBC_NAME}_2"
	if test "$LIBC_NAME" = glibc; then
		"$(get_hook builddep glibc)" "$HOST_ARCH" stage2
	else
		apt_get_build_dep "-a$HOST_ARCH" --arch-only ./
	fi
	(
		case "$LIBC_NAME:$ENABLE_MULTILIB" in
			glibc:yes) profiles=stage2 ;;
			glibc:no) profiles=stage2,nobiarch ;;
			*) profiles=cross,nocheck ;;
		esac
		# tell unmet build depends
		drop_privs dpkg-checkbuilddeps -B "-a$HOST_ARCH" "-P$profiles" || :
		export DEB_GCC_VERSION="-$GCC_VER"
		drop_privs_exec dpkg-buildpackage -B -uc -us "-a$HOST_ARCH" -d "-P$profiles" || buildpackage_failed "$?"
	)
	cd ..
	ls -l
	if test "$LIBC_NAME" = musl; then
		pickup_packages *.changes
		dpkg -i musl*.deb
	else
		if test "$ENABLE_MULTIARCH_GCC" = yes; then
			pickup_packages *.changes
			dpkg -i libc[0-9]*.deb
		else
			for pkg in libc[0-9]*.deb; do
				# dpkg-cross cannot handle these
				test "${pkg%%_*}" = "libc6-xen" && continue
				test "${pkg%%_*}" = "libc6.1-alphaev67" && continue
				drop_privs dpkg-cross -M -a "$HOST_ARCH" -X tzdata -X libc-bin -X libc-dev-bin -X multiarch-support -b "$pkg"
			done
			pickup_packages *.changes ./*-cross_*.deb
			dpkg -i libc[0-9]*-cross_*.deb
		fi
	fi
	touch "$REPODIR/stamps/${LIBC_NAME}_2"
	compare_native ./*.deb
	cd ..
	drop_privs rm -Rf "${LIBC_NAME}_2"
fi
progress_mark "$LIBC_NAME stage2 cross build"

if test -f "$REPODIR/stamps/gcc_3"; then
	echo "skipping rebuild of gcc stage3"
else
	apt_get_install debhelper gawk patchutils bison flex lsb-release quilt libtool $GCC_AUTOCONF zlib1g-dev libmpc-dev libmpfr-dev libgmp-dev dejagnu autogen systemtap-sdt-dev sharutils "binutils$HOST_ARCH_SUFFIX" time
	if test "$HOST_ARCH" = hppa; then
		apt_get_install binutils-hppa64-linux-gnu
	fi
	if test "$ENABLE_MULTIARCH_GCC" = yes; then
		apt_get_install "libc-dev:$HOST_ARCH" $(echo $MULTILIB_NAMES | sed "s/\(\S\+\)/libc6-dev-\1:$HOST_ARCH/g")
	else
		case "$LIBC_NAME" in
			glibc)
				apt_get_install "libc6-dev-$HOST_ARCH-cross" $(echo $MULTILIB_NAMES | sed "s/\(\S\+\)/libc6-dev-\1-$HOST_ARCH-cross/g")
			;;
			musl)
				apt_get_install "musl-dev-$HOST_ARCH-cross"
			;;
		esac
	fi
	cross_build_setup "gcc-$GCC_VER" gcc3
	check_binNMU
	dpkg-checkbuilddeps -a$HOST_ARCH || : # tell unmet build depends
	echo "$HOST_ARCH" > debian/target
	(
		nolang=${GCC_NOLANG:-}
		test "$ENABLE_MULTILIB" = yes || nolang=$(set_add "$nolang" biarch)
		export DEB_BUILD_OPTIONS="$DEB_BUILD_OPTIONS${nolang:+ nolang=$(join_words , $nolang)}"
		if test "$ENABLE_MULTIARCH_GCC" = yes; then
			export with_deps_on_target_arch_pkgs=yes
		else
			export WITH_SYSROOT=/
		fi
		export gcc_cv_libc_provides_ssp=yes
		export gcc_cv_initfini_array=yes
		drop_privs dpkg-buildpackage -d -T control
		drop_privs dpkg-buildpackage -d -T clean
		dpkg-checkbuilddeps || : # tell unmet build depends again after rewriting control
		drop_privs_exec dpkg-buildpackage -d -b -uc -us
	)
	cd ..
	ls -l
	if test "$ENABLE_MULTIARCH_GCC" = yes; then
		drop_privs changestool ./*.changes dumbremove "gcc-${GCC_VER}-base_"*"_$(dpkg --print-architecture).deb"
		drop_privs rm "gcc-${GCC_VER}-base_"*"_$(dpkg --print-architecture).deb"
	fi
	pickup_packages *.changes
	# avoid file conflicts between differently staged M-A:same packages
	apt_get_remove "gcc-$GCC_VER-base:$HOST_ARCH"
	drop_privs rm -fv gcc-*-plugin-*.deb gcj-*.deb gdc-*.deb ./*objc*.deb ./*-dbg_*.deb
	dpkg -i *.deb
	compiler="`dpkg-architecture -a$HOST_ARCH -qDEB_HOST_GNU_TYPE`-gcc-$GCC_VER"
	if ! which "$compiler"; then echo "$compiler missing in stage3 gcc package"; exit 1; fi
	if ! drop_privs "$compiler" -x c -c /dev/null -o test.o; then echo "stage3 gcc fails to execute"; exit 1; fi
	if ! test -f test.o; then echo "stage3 gcc fails to create binaries"; exit 1; fi
	check_arch test.o "$HOST_ARCH"
	mkdir -p "/usr/include/$(dpkg-architecture "-a$HOST_ARCH" -qDEB_HOST_MULTIARCH)"
	touch /usr/include/`dpkg-architecture -a$HOST_ARCH -qDEB_HOST_MULTIARCH`/include_path_test_header.h
	preproc="`dpkg-architecture -a$HOST_ARCH -qDEB_HOST_GNU_TYPE`-cpp-$GCC_VER"
	if ! echo '#include "include_path_test_header.h"' | drop_privs "$preproc" -E -; then echo "stage3 gcc fails to search /usr/include/<triplet>"; exit 1; fi
	touch "$REPODIR/stamps/gcc_3"
	if test "$ENABLE_MULTIARCH_GCC" = yes; then
		compare_native ./*.deb
	fi
	cd ..
	drop_privs rm -Rf gcc3
fi
progress_mark "cross gcc stage3 build"

if test "$ENABLE_MULTIARCH_GCC" != yes; then
if test -f "$REPODIR/stamps/gcc_f1"; then
	echo "skipping rebuild of gcc rtlibs"
else
	apt_get_install debhelper gawk patchutils bison flex lsb-release quilt libtool $GCC_AUTOCONF zlib1g-dev libmpc-dev libmpfr-dev libgmp-dev dejagnu autogen systemtap-sdt-dev sharutils "binutils$HOST_ARCH_SUFFIX" "libc-dev:$HOST_ARCH" time
	if test "$HOST_ARCH" = hppa; then
		apt_get_install binutils-hppa64-linux-gnu
	fi
	if test "$ENABLE_MULTILIB" = yes -a -n "$MULTILIB_NAMES"; then
		apt_get_install $(echo $MULTILIB_NAMES | sed "s/\(\S\+\)/libc6-dev-\1-$HOST_ARCH-cross libc6-dev-\1:$HOST_ARCH/g")
	fi
	cross_build_setup "gcc-$GCC_VER" gcc_f1
	check_binNMU
	dpkg-checkbuilddeps || : # tell unmet build depends
	echo "$HOST_ARCH" > debian/target
	(
		export DEB_STAGE=rtlibs
		nolang=${GCC_NOLANG:-}
		test "$ENABLE_MULTILIB" = yes || nolang=$(set_add "$nolang" biarch)
		export DEB_BUILD_OPTIONS="$DEB_BUILD_OPTIONS${nolang:+ nolang=$(join_words , $nolang)}"
		export WITH_SYSROOT=/
		drop_privs dpkg-buildpackage -d -T control
		cat debian/control
		dpkg-checkbuilddeps || : # tell unmet build depends again after rewriting control
		drop_privs_exec dpkg-buildpackage -d -b -uc -us
	)
	cd ..
	ls -l
	rm -vf "gcc-$GCC_VER-base_"*"_$(dpkg --print-architecture).deb"
	pickup_additional_packages *.deb
	$APT_GET dist-upgrade
	dpkg -i ./*.deb
	touch "$REPODIR/stamps/gcc_f1"
	cd ..
	drop_privs rm -Rf gcc_f1
fi
progress_mark "gcc cross rtlibs build"
fi

# install something similar to crossbuild-essential
apt_get_install "binutils$HOST_ARCH_SUFFIX" "gcc-$GCC_VER$HOST_ARCH_SUFFIX" "g++-$GCC_VER$HOST_ARCH_SUFFIX" "libc-dev:$HOST_ARCH"

apt_get_remove libc6-i386 # breaks cross builds

if dpkg-architecture "-a$HOST_ARCH" -ihurd-any; then
if test -f "$REPODIR/stamps/hurd_2"; then
	echo "skipping rebuild of hurd stage2"
else
	cross_build_setup hurd hurd_2
	apt_get_build_dep "-a$HOST_ARCH" --arch-only -P stage2 ./
	drop_privs dpkg-buildpackage -B "-a$HOST_ARCH" -Pstage2 -uc -us
	cd ..
	ls -l
	pickup_packages *.changes
	touch "$REPODIR/stamps/hurd_2"
	cd ..
	drop_privs rm -Rf hurd_2
fi
apt_get_install "hurd-dev:$HOST_ARCH"
progress_mark "hurd stage3 cross build"
fi

# Skip libxcrypt for musl until #947193 is resolved.
if ! dpkg-architecture "-a$HOST_ARCH" -i musl-linux-any; then
	# libcrypt1-dev is defacto build-essential, because unstaged libc6-dev (and
	# later build-essential) depends on it.
	cross_build libxcrypt
	apt_get_install "libcrypt1-dev:$HOST_ARCH"
	# is defacto build-essential
fi

apt_get_install dose-builddebcheck dctrl-tools

call_dose_builddebcheck() {
	local package_list source_list errcode
	package_list=`mktemp packages.XXXXXXXXXX`
	source_list=`mktemp sources.XXXXXXXXXX`
	cat /var/lib/apt/lists/*_Packages - > "$package_list" <<EOF
Package: crossbuild-essential-$HOST_ARCH
Version: 0
Architecture: $HOST_ARCH
Multi-Arch: foreign
Depends: libc-dev
Description: fake crossbuild-essential package for dose-builddebcheck

EOF
	sed -i -e '/^Conflicts:.* libc[0-9][^ ]*-dev\(,\|$\)/d' "$package_list" # also make dose ignore the glibc conflict
	apt-cache show "gcc-${GCC_VER}-base=installed" libgcc-s1=installed libstdc++6=installed libatomic1=installed >> "$package_list" # helps when pulling gcc from experimental
	cat /var/lib/apt/lists/*_Sources > "$source_list"
	errcode=0
	dose-builddebcheck --deb-tupletable=/usr/share/dpkg/tupletable --deb-cputable=/usr/share/dpkg/cputable "--deb-native-arch=$(dpkg --print-architecture)" "--deb-host-arch=$HOST_ARCH" "$@" "$package_list" "$source_list" || errcode=$?
	if test "$errcode" -gt 1; then
		echo "dose-builddebcheck failed with error code $errcode" 1>&2
		exit 1
	fi
	rm -f "$package_list" "$source_list"
}

# determine whether a given binary package refers to an arch:all package
# $1 is a binary package name
is_arch_all() {
	grep-dctrl -P -X "$1" -a -F Architecture all -s /var/lib/apt/lists/*_Packages
}

# determine which source packages build a given binary package
# $1 is a binary package name
# prints a set of source packages
what_builds() {
	local newline pattern source
	newline='
'
	pattern=`echo "$1" | sed 's/[+.]/\\\\&/g'`
	pattern="$newline $pattern "
	# exit codes 0 and 1 signal successful operation
	source=`grep-dctrl -F Package-List -e "$pattern" -s Package -n /var/lib/apt/lists/*_Sources || test "$?" -eq 1`
	set_create "$source"
}

# determine a set of source package names which are essential to some
# architecture
discover_essential() {
	set_create "$(grep-dctrl -F Package-List -e '\bessential=yes\b' -s Package -n /var/lib/apt/lists/*_Sources)"
}

need_packages=
add_need() { need_packages=`set_add "$need_packages" "$1"`; }
built_packages=
mark_built() {
	need_packages=`set_discard "$need_packages" "$1"`
	built_packages=`set_add "$built_packages" "$1"`
}

for pkg in $(discover_essential); do
	if set_contains "$automatic_packages" "$pkg"; then
		echo "rebootstrap-debug: automatically scheduling essential package $pkg"
		add_need "$pkg"
	else
		echo "rebootstrap-debug: not scheduling essential package $pkg"
	fi
done
add_need acl # by coreutils, systemd
add_need apt # almost essential
add_need attr # by coreutils, libcap-ng
add_need autogen # by gcc-VER, gnutls28
add_need blt # by pythonX.Y
add_need bsdmainutils # for man-db
add_need bzip2 # by perl
add_need db-defaults # by perl, python2.7, python3.5
add_need expat # by unbound
add_need file # by gcc-6, for debhelper
add_need flex # by libsemanage, pam
add_need fribidi # by newt
add_need gmp # by gnutls28
add_need gnupg2 # for apt
test "$(dpkg-architecture "-a$HOST_ARCH" -qDEB_HOST_ARCH_OS)" = linux && add_need gpm # by ncurses
add_need groff # for man-db
test "$(dpkg-architecture "-a$HOST_ARCH" -qDEB_HOST_ARCH_OS)" = linux && add_need kmod # by systemd
add_need icu # by libxml2
add_need krb5 # by audit
add_need libatomic-ops # by gcc-VER
dpkg-architecture "-a$HOST_ARCH" -ilinux-any && add_need libcap2 # by systemd
add_need libdebian-installer # by cdebconf
add_need libevent # by unbound
add_need libidn2 # by gnutls28
add_need libgcrypt20 # by libprelude, cryptsetup
dpkg-architecture "-a$HOST_ARCH" -ilinux-any && add_need libsepol # by libselinux
if dpkg-architecture "-a$HOST_ARCH" -ihurd-any; then
	add_need libsystemd-dummy # by nghttp2
fi
add_need libtasn1-6 # by gnutls28
add_need libtextwrap # by cdebconf
add_need libunistring # by gnutls28
add_need libxrender # by cairo
add_need libzstd # by systemd
add_need lz4 # by systemd
add_need make-dfsg # for build-essential
add_need man-db # for debhelper
add_need mawk # for base-files (alternatively: gawk)
add_need mpclib3 # by gcc-VER
add_need mpdecimal # by python3.X
add_need mpfr4 # by gcc-VER
add_need nettle # by unbound, gnutls28
add_need openssl # by cyrus-sasl2
add_need p11-kit # by gnutls28
add_need patch # for dpkg-dev
add_need pcre2 # by libselinux
add_need popt # by newt
add_need slang2 # by cdebconf, newt
add_need sqlite3 # by python2.7
add_need tcl8.6 # by newt
add_need tcltk-defaults # by python2.7
add_need tcp-wrappers # by audit
add_need xz-utils # by libxml2

automatically_cross_build_packages() {
	local dosetmp profiles buildable new_needed line pkg missing source
	while test -n "$need_packages"; do
		echo "checking packages with dose-builddebcheck: $need_packages"
		dosetmp=`mktemp -t doseoutput.XXXXXXXXXX`
		profiles="$DEFAULT_PROFILES"
		if test "$ENABLE_MULTILIB" = no; then
			profiles=$(set_add "$profiles" nobiarch)
		fi
		call_dose_builddebcheck --successes --failures --explain --latest=1 --deb-drop-b-d-indep "--deb-profiles=$(join_words , $profiles)" "--checkonly=$(join_words , $need_packages)" >"$dosetmp"
		buildable=
		new_needed=
		while IFS= read -r line; do
			case "$line" in
				"  package: "*)
					pkg=${line#  package: }
					pkg=${pkg#src:} # dose3 << 4.1
				;;
				"  status: ok")
					buildable=`set_add "$buildable" "$pkg"`
				;;
				"      unsat-dependency: "*)
					missing=${line#*: }
					missing=${missing%% | *} # drop alternatives
					missing=${missing% (* *)} # drop version constraint
					missing=${missing%:$HOST_ARCH} # skip architecture
					if is_arch_all "$missing"; then
						echo "rebootstrap-warning: $pkg misses dependency $missing which is arch:all"
					else
						source=`what_builds "$missing"`
						case "$source" in
							"")
								echo "rebootstrap-warning: $pkg transitively build-depends on $missing, but no source package could be determined"
							;;
							*" "*)
								echo "rebootstrap-warning: $pkg transitively build-depends on $missing, but it is build from multiple source packages: $source"
							;;
							*)
								if set_contains "$built_packages" "$source"; then
									echo "rebootstrap-warning: $pkg transitively build-depends on $missing, which is built from $source, which is supposedly already built"
								elif set_contains "$need_packages" "$source"; then
									echo "rebootstrap-debug: $pkg transitively build-depends on $missing, which is built from $source and already scheduled for building"
								elif set_contains "$automatic_packages" "$source"; then
									new_needed=`set_add "$new_needed" "$source"`
								else
									echo "rebootstrap-warning: $pkg transitively build-depends on $missing, which is built from $source but not automatic"
								fi
							;;
						esac
					fi
				;;
			esac
		done < "$dosetmp"
		rm "$dosetmp"
		echo "buildable packages: $buildable"
		echo "new packages needed: $new_needed"
		test -z "$buildable" -a -z "$new_needed" && break
		for pkg in $buildable; do
			echo "cross building $pkg"
			cross_build "$pkg"
			mark_built "$pkg"
		done
		need_packages=`set_union "$need_packages" "$new_needed"`
	done
	echo "done automatically cross building packages. left: $need_packages"
}

assert_built() {
	local missing_pkgs profiles
	missing_pkgs=`set_difference "$1" "$built_packages"`
	test -z "$missing_pkgs" && return 0
	echo "rebootstrap-error: missing asserted packages: $missing_pkgs"
	missing_pkgs=`set_union "$missing_pkgs" "$need_packages"`
	profiles="$DEFAULT_PROFILES"
	if test "$ENABLE_MULTILIB" = no; then
		profiles=$(set_add "$profiles" nobiarch)
	fi
	call_dose_builddebcheck --failures --explain --latest=1 --deb-drop-b-d-indep "--deb-profiles=$(join_words , $profiles)" "--checkonly=$(join_words , $missing_pkgs)"
	return 1
}

automatically_cross_build_packages

cross_build zlib "$(if test "$ENABLE_MULTILIB" != yes; then echo stage1; fi)"
mark_built zlib
# needed by dpkg, file, gnutls28, libpng1.6, libtool, libxml2, perl, slang2, tcl8.6, util-linux

automatically_cross_build_packages

cross_build libtool
mark_built libtool
# needed by guile-X.Y, libffi

automatically_cross_build_packages

cross_build ncurses
mark_built ncurses
# needed by bash, bsdmainutils, dpkg, guile-X.Y, readline, slang2

automatically_cross_build_packages

cross_build readline
mark_built readline
# needed by gnupg2, guile-X.Y, libxml2

automatically_cross_build_packages

if dpkg-architecture "-a$HOST_ARCH" -ilinux-any; then
	assert_built "libsepol pcre2"
	cross_build libselinux "nopython noruby" libselinux_1
	mark_built libselinux
# needed by coreutils, dpkg, findutils, glibc, sed, tar, util-linux

automatically_cross_build_packages
fi # $HOST_ARCH matches linux-any

dpkg-architecture "-a$1" -ilinux-any && assert_built libselinux
assert_built "ncurses zlib"
cross_build util-linux "stage1 pkg.util-linux.noverity" util-linux_1
mark_built util-linux
# essential, needed by e2fsprogs

automatically_cross_build_packages

cross_build db5.3 "pkg.db5.3.notcl nojava" db5.3_1
mark_built db5.3
# needed by perl, python2.7, needed for db-defaults

automatically_cross_build_packages

cross_build libxml2 nopython libxml2_1
mark_built libxml2
# needed by autogen

automatically_cross_build_packages

cross_build cracklib2 nopython cracklib2_1
mark_built cracklib2
# needed by pam

automatically_cross_build_packages

cross_build build-essential
mark_built build-essential
# build-essential

automatically_cross_build_packages

cross_build pam stage1 pam_1
mark_built pam
# needed by shadow

automatically_cross_build_packages

cross_build cyrus-sasl2 pkg.cyrus-sasl2.nogssapi,pkg.cyrus-sasl2.noldap,pkg.cyrus-sasl2.nosql cyrus-sask2_1
mark_built cyrus-sasl2
# needed by openldap

automatically_cross_build_packages

assert_built "libevent expat nettle"
dpkg-architecture "-a$HOST_ARCH" -ilinux-any || assert_built libbsd
cross_build unbound pkg.unbound.libonly unbound_1
mark_built unbound
# needed by gnutls28

automatically_cross_build_packages

assert_built "gmp libidn2 autogen p11-kit libtasn1-6 unbound libunistring nettle"
cross_build gnutls28 noguile gnutls28_1
mark_built gnutls28
# needed by libprelude, openldap, curl

automatically_cross_build_packages

assert_built "gnutls28 cyrus-sasl2"
cross_build openldap pkg.openldap.noslapd openldap_1
mark_built openldap
# needed by curl

automatically_cross_build_packages

if apt-cache showsrc systemd | grep -q "^Build-Depends:.*gnu-efi[^,]*[[ ]$HOST_ARCH[] ]"; then
cross_build gnu-efi
mark_built gnu-efi
# needed by systemd

automatically_cross_build_packages
fi

if test "$(dpkg-architecture "-a$HOST_ARCH" -qDEB_HOST_ARCH_OS)" = linux; then
if apt-cache showsrc man-db systemd | grep -q "^Build-Depends:.*libseccomp-dev[^,]*[[ ]$HOST_ARCH[] ]"; then
	cross_build libseccomp nopython libseccomp_1
	mark_built libseccomp
# needed by man-db, systemd

	automatically_cross_build_packages
fi


assert_built "libcap2 pam libselinux acl xz-utils libgcrypt20 kmod util-linux libzstd"
if apt-cache showsrc systemd | grep -q "^Build-Depends:.*libseccomp-dev[^,]*[[ ]$HOST_ARCH[] ]" debian/control; then
	assert_built libseccomp
fi
cross_build systemd stage1 systemd_1
mark_built systemd
# needed by util-linux

automatically_cross_build_packages

assert_built attr
cross_build libcap-ng nopython libcap-ng_1
mark_built libcap-ng
# needed by audit

automatically_cross_build_packages

assert_built "gnutls28 libgcrypt20 libtool"
cross_build libprelude "nolua noperl nopython noruby" libprelude_1
mark_built libprelude
# needed by audit

automatically_cross_build_packages

assert_built "zlib bzip2 xz-utils"
cross_build elfutils pkg.elfutils.nodebuginfod
mark_built elfutils
# needed by glib2.0

automatically_cross_build_packages

assert_built "libcap-ng krb5 openldap libprelude tcp-wrappers"
cross_build audit nopython audit_1
mark_built audit
# needed by libsemanage

automatically_cross_build_packages

assert_built "audit bzip2 libselinux libsepol"
cross_build libsemanage "nocheck nopython noruby" libsemanage_1
mark_built libsemanage
# needed by shadow

automatically_cross_build_packages
fi # $HOST_ARCH matches linux-any

dpkg-architecture "-a$1" -ilinux-any && assert_built "audit libcap-ng libselinux systemd"
assert_built "ncurses zlib"
cross_build util-linux "pkg.util-linux.noverity"
# essential

automatically_cross_build_packages

cross_build brotli nopython brotli_1
mark_built brotli
# needed by curl

automatically_cross_build_packages

cross_build gdbm pkg.gdbm.nodietlibc gdbm_1
mark_built gdbm
# needed by man-db, perl, python2.7

automatically_cross_build_packages

cross_build newt nopython newt_1
mark_built newt
# needed by cdebconf

automatically_cross_build_packages

cross_build cdebconf pkg.cdebconf.nogtk cdebconf_1
mark_built cdebconf
# needed by base-passwd

automatically_cross_build_packages

if test -f "$REPODIR/stamps/binutils_2"; then
	echo "skipping cross rebuild of binutils"
else
	cross_build_setup binutils binutils_2
	apt_get_build_dep "-a$HOST_ARCH" --arch-only -P nocheck ./
	check_binNMU
	drop_privs dpkg-buildpackage "-a$HOST_ARCH" -Pnocheck -B -uc -us
	cd ..
	ls -l
	drop_privs sed -i -e '/^ .* binutils-for-host_.*deb$/d' ./*.changes
	pickup_additional_packages *.changes
	touch "$REPODIR/stamps/binutils_2"
	compare_native ./*.deb
	cd ..
	drop_privs rm -Rf binutils_2
fi
progress_mark "cross build binutils"
mark_built binutils
# needed for build-essential

automatically_cross_build_packages

assert_built "$need_packages"

echo "checking installability of build-essential with dose"
apt_get_install botch
package_list=$(mktemp -t packages.XXXXXXXXXX)
grep-dctrl --exact --field Architecture '(' "$HOST_ARCH" --or all ')' /var/lib/apt/lists/*_Packages > "$package_list"
botch-distcheck-more-problems "--deb-native-arch=$HOST_ARCH" --successes --failures --explain --checkonly "build-essential:$HOST_ARCH" "--bg=deb://$package_list" "--fg=deb://$package_list" || :
rm -f "$package_list"
