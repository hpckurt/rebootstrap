#!/bin/sh

set -v
set -e
set -u

export DEB_BUILD_OPTIONS="nocheck noddebs parallel=1"
export DH_VERBOSE=1
HOST_ARCH=undefined
# select gcc version from gcc-defaults package unless set
GCC_VER=
: "${MIRROR:=http://deb.debian.org/debian}"
ENABLE_MULTILIB=no
ENABLE_MULTIARCH_GCC=yes
REPODIR=/tmp/repo
# https://salsa.debian.org/apt-team/apt#debugging
APT_GET="apt-get --no-install-recommends -y -o Debug::pkgProblemResolver=true -o Debug::pkgDepCache::Marker=1 -o Debug::pkgDepCache::AutoInstall=1 -o Acquire::Languages=none"
DEFAULT_PROFILES="cross nocheck noinsttest noudeb"
DROP_PRIVS=buildd
GCC_NOLANG="ada algol asan brig cobol d gcn go itm java jit hppa64 lsan m2 nvptx objc obj-c++ rust tsan ubsan"
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
			"arc:ELF 32-bit LSB relocatable, *unknown arch 0xc3* version 1 (SYSV)"*|"arc:ELF 32-bit LSB relocatable, Synopsys ARCv2/HS3x/HS4x cores, version 1 (SYSV)"*)
				return 0
			;;
			"csky:ELF 32-bit LSB relocatable, *unknown arch 0xfc* version 1 (SYSV)"*|"csky:ELF 32-bit LSB relocatable, C-SKY processor family, version 1 (SYSV)"*)
				return 0
			;;
			"loong64:ELF 64-bit LSB relocatable, LoongArch, version 1 (SYSV)"*)
				return 0
			;;
			"mips64r6el:ELF 32-bit LSB relocatable, MIPS, MIPS64 rel6 version 1 (SYSV)"*)
				# elf-arch only recognizes some of the binaries but not others.
				return 0
			;;
			"riscv32:ELF 32-bit LSB relocatable, UCB RISC-V, double-float ABI, version 1 (SYSV)"*|"riscv32:ELF 32-bit LSB relocatable, UCB RISC-V, RVC, double-float ABI, version 1 (SYSV)"*)
				# https://github.com/kilobyte/arch-test/pull/11
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

if test -z "$GCC_VER"; then
	GCC_VER=`apt-cache depends gcc | sed 's/^ *Depends: gcc-\([0-9.]*\)$/\1/;t;d'`
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

cat <<EOF >> /usr/share/dpkg/cputable
csky		csky		csky		32	little
EOF

if test -z "$HOST_ARCH" || ! dpkg-architecture "-a$HOST_ARCH"; then
	echo "architecture $HOST_ARCH unknown to dpkg"
	exit 1
fi

# ensure that the rebootstrap list comes first
test -f /etc/apt/sources.list && mv -v /etc/apt/sources.list /etc/apt/sources.list.d/local.list
grep -q '^deb-src .*sid' /etc/apt/sources.list.d/*.list || echo "deb-src $MIRROR sid main" >> /etc/apt/sources.list.d/sid-source.list

dpkg --add-architecture "$HOST_ARCH"
$APT_GET update

rm -Rf /tmp/buildd
drop_privs mkdir -p /tmp/buildd

HOST_ARCH_SUFFIX="-$(dpkg-architecture "-a$HOST_ARCH" -qDEB_HOST_GNU_TYPE | tr _ -)"

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

for f in /etc/apt/sources.list.d/*.list; do
	test -f "$f" && sed -i "s/^deb \(\[.*\] \)*/deb [ arch-=$HOST_ARCH ] /" "$f"
done
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

# debhelper/13.10 started trimming changelogs, this breaks all over the place
cat >/etc/dpkg/dpkg.cfg.d/trimmed-changelogs <<'EOF'
path-exclude=/usr/share/doc/*/changelog.Debian.gz
path-exclude=/usr/share/doc/*/changelog.gz
path-exclude=/usr/share/doc/*/NEWS.Debian.gz
EOF

if dpkg-architecture "-a$HOST_ARCH" -imusl-any-any; then
	echo "disabling symbol checking for musl architectures for all builds, as the musl linker does no support symbol versioning"
	# https://wiki.musl-libc.org/functional-differences-from-glibc.html#Symbol-versioning
	export DPKG_GENSYMBOLS_CHECK_LEVEL=0
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
			i=$((i + 1))
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
			add_binNMU_changelog "${maxversion#"$srcversion+b"}" "Bump to binNMU version of $(dpkg --print-architecture)."
		;;
	esac
}

PROGRESS_MARK=1
progress_mark() {
	echo "progress-mark:$PROGRESS_MARK:$*"
	PROGRESS_MARK=$((PROGRESS_MARK + 1))
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

if test "$ENABLE_MULTIARCH_GCC" != yes; then
	apt_get_install dpkg-cross
fi

automatic_packages=
add_automatic() { automatic_packages=$(set_add "$automatic_packages" "$1"); }

add_automatic acl
add_automatic apt
add_automatic attr
add_automatic base-files
add_automatic base-passwd
add_automatic bash

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
	case "$HOST_ARCH" in loong64|sparc)
		echo "enabling uncommon architectures in debian/control"
		drop_privs sed -i -e "/^#NATIVE_ARCHS +=/aNATIVE_ARCHS += $HOST_ARCH" debian/rules
		drop_privs ./debian/rules ./stamps/control
		drop_privs rm -f ./stamps/control
	;; esac
}

add_automatic blt

add_automatic bsdmainutils
patch_bsdmainutils() {
	dpkg-architecture "-a$HOST_ARCH" -imusl-any-any || return 0
	echo "there is no sys/cdefs.h on musl #1086236"
	drop_privs patch -p1 <<'EOF'
--- /dev/null
+++ b/debian/patches/musl.patch
@@ -0,0 +1,30 @@
+--- a/usr.bin/ncal/calendar.c
++++ b/usr.bin/ncal/calendar.c
+@@ -26,7 +26,6 @@
+  * SUCH DAMAGE.
+  */
+
+-#include <sys/cdefs.h>
+ #include <langinfo.h>
+ __FBSDID("$FreeBSD: head/lib/libcalendar/calendar.c 326219 2017-11-26 02:00:33Z pfg $");
+
+--- bsdmainutils-12.1.8.orig/usr.bin/ncal/easter.c
++++ bsdmainutils-12.1.8/usr.bin/ncal/easter.c
+@@ -26,7 +26,6 @@
+  * SUCH DAMAGE.
+  */
+
+-#include <sys/cdefs.h>
+ __FBSDID("$FreeBSD: head/lib/libcalendar/easter.c 326219 2017-11-26 02:00:33Z pfg $");
+
+ #include "calendar.h"
+--- bsdmainutils-12.1.8.orig/usr.bin/ncal/ncal.c
++++ bsdmainutils-12.1.8/usr.bin/ncal/ncal.c
+@@ -26,7 +26,6 @@
+  * SUCH DAMAGE.
+  */
+
+-#include <sys/cdefs.h>
+ __FBSDID("$FreeBSD: head/usr.bin/ncal/ncal.c 359419 2020-03-29 04:18:27Z grog $");
+
+ #include "calendar.h"
--- a/debian/patches/series
+++ b/debian/patches/series
@@ -17,3 +17,4 @@
 fix-big-1stweek.patch
 cal_highlight.diff
 ncal_input.diff
+musl.patch
EOF
}

builddep_build_essential() {
	# g++ dependency needs cross translation
	apt_get_install debhelper python3
}

add_automatic bzip2
add_automatic c-ares

patch_cdebconf() {
	echo "removing libglib2.0-dev depencency #1078936"
	drop_privs patch -p1 <<'EOF'
--- a/debian/control
+++ b/debian/control
@@ -9,12 +9,13 @@
  libtextwrap-dev,
  libreadline-dev (>= 8.1.2-1.1),
  libdebian-installer4-dev | libdebian-installer-dev,
- libglib2.0-dev,
+ libglib2.0-dev <!pkg.cdebconf.nogtk>,
  libgtk2.0-dev <!pkg.cdebconf.nogtk>,
  libcairo2-dev <!pkg.cdebconf.nogtk>,
  libselinux1-dev [linux-any] | libselinux-dev [linux-any],
  dh-autoreconf,
  dh-exec,
+ pkgconf,
 Maintainer: Debian Install System Team <debian-boot@lists.debian.org>
 Uploaders:
  Colin Watson <cjwatson@debian.org>,
EOF
}

add_automatic coreutils
add_automatic curl

patch_cyrus_sasl2() {
	echo "fix FTCBFS #1101329"
	sed -i -e 's/python3-sphinx /python3-sphinx:native /' debian/control
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
patch_flex() {
	test "$GCC_VER" -lt 15 && return 0
	echo "fix FTCBFS with gcc-15 #1098516"
	drop_privs patch -p1 <<'EOF'
--- a/lib/malloc.c
+++ b/lib/malloc.c
@@ -3,7 +3,7 @@
      
      #include <sys/types.h>
      
-     void *malloc ();
+     void *malloc (size_t);
      
      /* Allocate an N-byte block of memory from the heap.
         If N is zero, allocate a 1-byte block.  */
EOF
}

add_automatic fontconfig
add_automatic freetype
add_automatic fribidi
add_automatic fuse3

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
 	  include_dir=include$${multi_dir}; \
-	  if $(LIMITS_H_TEST) ; then \
-	    cat $(srcdir)/limitx.h $(T_GLIMITS_H) $(srcdir)/limity.h > tmp-xlimits.h; \
-	  else \
-	    cat $(T_GLIMITS_H) > tmp-xlimits.h; \
-	  fi; \
+	  cat $(srcdir)/limitx.h $(T_GLIMITS_H) $(srcdir)/limity.h > tmp-xlimits.h; \
 	  $(mkinstalldirs) $${include_dir}; \
 	  chmod a+rx $${include_dir} || true; \
 	  $(SHELL) $(srcdir)/../move-if-change \
EOF
	echo "debian_patches += limits-h-test" | drop_privs tee -a debian/rules.patch >/dev/null
}
patch_gcc_for_host_in_rtlibs() {
	echo "moving -for-host packages to rlibs build #1069065"
	drop_privs patch -p1 <<'EOF'
--- a/debian/control.m4
+++ b/debian/control.m4
@@ -800,19 +800,6 @@
  a fairly portable optimizing compiler for C.
 ')`'dnl for_each_arch

-Package: gcc`'PV`'-for-host
-Architecture: ifdef(`TARGET',`TARGET',`any')
-TARGET_PACKAGE`'dnl
-Multi-Arch: same
-Depends: BASEDEP, gcc`'PV`'${target:suffix} (>= ${gcc:SoftVersion}),
-  cpp`'PV`'-for-host (= ${gcc:Version}), ${misc:Depends}
-BUILT_USING`'dnl
-Description: GNU C compiler for the host architecture
- This is the GNU C compiler, a fairly portable optimizing compiler for C.
- .
- When using this package, tools must be invoked with an architecture prefix.
- .
- This is a dependency package.
 ifdef(`TARGET',`',`
 Package: gcc`'PV`'-for-build
 Architecture: all
@@ -892,6 +879,22 @@
 ')`'dnl plugindev
 ')`'dnl cdev

+ifenabled(`gccforhost',`dnl
+Package: gcc`'PV`'-for-host
+Architecture: ifdef(`TARGET',`TARGET',`any')
+TARGET_PACKAGE`'dnl
+Multi-Arch: same
+Depends: BASEDEP, gcc`'PV`'${target:suffix} (>= ${gcc:SoftVersion}),
+  cpp`'PV`'-for-host (= ${gcc:Version}), ${misc:Depends}
+BUILT_USING`'dnl
+Description: GNU C compiler for the host architecture
+ This is the GNU C compiler, a fairly portable optimizing compiler for C.
+ .
+ When using this package, tools must be invoked with an architecture prefix.
+ .
+ This is a dependency package.
+')`'dnl gccforhost
+
 ifenabled(`cdev',`
 Package: gcc`'PV-hppa64-linux-gnu
 Architecture: ifdef(`TARGET',`any',hppa amd64 i386 x32)
@@ -924,24 +927,6 @@
  the compiler.
 ')`'dnl for_each_arch

-Package: cpp`'PV`'-for-host
-Architecture: ifdef(`TARGET',`TARGET',`any')
-TARGET_PACKAGE`'dnl
-Multi-Arch: same
-Section: ifdef(`TARGET',`devel',`interpreters')
-Depends: BASEDEP, cpp`'PV`'${target:suffix} (>= ${gcc:SoftVersion}), ${misc:Depends}
-BUILT_USING`'dnl
-Description: GNU C preprocessor for the host architecture
- A macro processor that is used automatically by the GNU C compiler
- to transform programs before actual compilation.
- .
- This package has been separated from gcc for the benefit of those who
- require the preprocessor configured for the host architecture but not
- the compiler.
- .
- When using this package, tools must be invoked with an architecture prefix.
- .
- This is a dependency package.
 ifdef(`TARGET',`',`
 Package: cpp`'PV`'-for-build
 Architecture: all
@@ -999,6 +984,27 @@
 ')`'dnl native
 ')`'dnl cdev

+ifenabled(`cppforhost',`dnl
+Package: cpp`'PV`'-for-host
+Architecture: ifdef(`TARGET',`TARGET',`any')
+TARGET_PACKAGE`'dnl
+Multi-Arch: same
+Section: ifdef(`TARGET',`devel',`interpreters')
+Depends: BASEDEP, cpp`'PV`'${target:suffix} (>= ${gcc:SoftVersion}), ${misc:Depends}
+BUILT_USING`'dnl
+Description: GNU C preprocessor for the host architecture
+ A macro processor that is used automatically by the GNU C compiler
+ to transform programs before actual compilation.
+ .
+ This package has been separated from gcc for the benefit of those who
+ require the preprocessor configured for the host architecture but not
+ the compiler.
+ .
+ When using this package, tools must be invoked with an architecture prefix.
+ .
+ This is a dependency package.
+')`'dnl cppforhost
+
 ifenabled(`c++',`
 ifenabled(`c++dev',`dnl
 for_each_arch(`
@@ -1015,21 +1021,6 @@
  This package contains C++ cross-compiler for arch_gnu architecture.
 ')`'dnl for_each_arch

-Package: g++`'PV`'-for-host
-Architecture: ifdef(`TARGET',`TARGET',`any')
-TARGET_PACKAGE`'dnl
-Multi-Arch: same
-Depends: BASEDEP, g++`'PV`'${target:suffix} (>= ${gcc:SoftVersion}),
-  gcc`'PV`'-for-host (= ${gcc:Version}), ${misc:Depends}
-BUILT_USING`'dnl
-Description: GNU C++ compiler for the host architecture
- This is the GNU C++ compiler, a fairly portable optimizing compiler for C++.
- .
- This package contains C++ cross-compiler for the host architecture.
- .
- When using this package, tools must be invoked with an architecture prefix.
- .
- This is a dependency package.
 ifdef(`TARGET',`',`
 Package: g++`'PV`'-for-build
 Architecture: all
@@ -1071,6 +1062,24 @@
 ')`'dnl c++dev
 ')`'dnl c++

+ifenabled(`c++forhost',`dnl
+Package: g++`'PV`'-for-host
+Architecture: ifdef(`TARGET',`TARGET',`any')
+TARGET_PACKAGE`'dnl
+Multi-Arch: same
+Depends: BASEDEP, g++`'PV`'${target:suffix} (>= ${gcc:SoftVersion}),
+  gcc`'PV`'-for-host (= ${gcc:Version}), ${misc:Depends}
+BUILT_USING`'dnl
+Description: GNU C++ compiler for the host architecture
+ This is the GNU C++ compiler, a fairly portable optimizing compiler for C++.
+ .
+ This package contains C++ cross-compiler for the host architecture.
+ .
+ When using this package, tools must be invoked with an architecture prefix.
+ .
+ This is a dependency package.
+')`'dnl c++forhost
+
 ifdef(`TARGET', `', `
 ifenabled(`ssp',`
 Package: libssp`'SSP_SO`'LS
@@ -2518,22 +2527,6 @@
  It uses the gcc backend to generate optimized code.
 ')`'dnl for_each_arch

-Package: gobjc++`'PV`'-for-host
-Architecture: ifdef(`TARGET',`TARGET',`any')
-TARGET_PACKAGE`'dnl
-Multi-Arch: same
-Depends: BASEDEP, gobjc++`'PV`'${target:suffix} (>= ${gcc:SoftVersion}),
-  gobjc`'PV`'-for-host (= ${gcc:Version}), g++`'PV`'-for-host (= ${gcc:Version}),
-  ${misc:Depends}
-BUILT_USING`'dnl
-Description: GNU Objective-C++ compiler for the host architecture
- This is the GNU Objective-C++ compiler for the host architecture,
- which compiles Objective-C++ on platforms supported by the gcc compiler.
- It uses the gcc backend to generate optimized code.
- .
- When using this package, tools must be invoked with an architecture prefix.
- .
- This is a dependency package.
 ifdef(`TARGET',`',`
 Package: gobjc++`'PV`'-for-build
 Architecture: all
@@ -2563,6 +2556,25 @@
 ')`'dnl TARGET
 ')`'dnl obcppdev

+ifenabled(`objppforhost',`dnl
+Package: gobjc++`'PV`'-for-host
+Architecture: ifdef(`TARGET',`TARGET',`any')
+TARGET_PACKAGE`'dnl
+Multi-Arch: same
+Depends: BASEDEP, gobjc++`'PV`'${target:suffix} (>= ${gcc:SoftVersion}),
+  gobjc`'PV`'-for-host (= ${gcc:Version}), g++`'PV`'-for-host (= ${gcc:Version}),
+  ${misc:Depends}
+BUILT_USING`'dnl
+Description: GNU Objective-C++ compiler for the host architecture
+ This is the GNU Objective-C++ compiler for the host architecture,
+ which compiles Objective-C++ on platforms supported by the gcc compiler.
+ It uses the gcc backend to generate optimized code.
+ .
+ When using this package, tools must be invoked with an architecture prefix.
+ .
+ This is a dependency package.
+')`'dnl objppforhost
+
 ifenabled(`multilib',`
 Package: gobjc++`'PV-multilib`'TS
 Architecture: ifdef(`TARGET',`any',MULTILIB_ARCHS)
@@ -2595,21 +2607,6 @@
  It uses the gcc backend to generate optimized code.
 ')`'dnl for_each_arch

-Package: gobjc`'PV`'-for-host
-Architecture: ifdef(`TARGET',`TARGET',`any')
-TARGET_PACKAGE`'dnl
-Multi-Arch: same
-Depends: BASEDEP, gobjc`'PV`'${target:suffix} (>= ${gcc:SoftVersion}),
-  gcc`'PV`'-for-host (= ${gcc:Version}), ${misc:Depends}
-BUILT_USING`'dnl
-Description: GNU Objective-C compiler for the host architecture
- This is the GNU Objective-C compiler for the host architecture,
- which compiles Objective-C on platforms supported by the gcc compiler.
- It uses the gcc backend to generate optimized code.
- .
- When using this package, tools must be invoked with an architecture prefix.
- .
- This is a dependency package.
 ifdef(`TARGET',`',`
 Package: gobjc`'PV`'-for-build
 Architecture: all
@@ -2705,6 +2702,24 @@
 ')`'dnl libx32objc
 ')`'dnl objcdev

+ifenabled(`objcforhost',`dnl
+Package: gobjc`'PV`'-for-host
+Architecture: ifdef(`TARGET',`TARGET',`any')
+TARGET_PACKAGE`'dnl
+Multi-Arch: same
+Depends: BASEDEP, gobjc`'PV`'${target:suffix} (>= ${gcc:SoftVersion}),
+  gcc`'PV`'-for-host (= ${gcc:Version}), ${misc:Depends}
+BUILT_USING`'dnl
+Description: GNU Objective-C compiler for the host architecture
+ This is the GNU Objective-C compiler for the host architecture,
+ which compiles Objective-C on platforms supported by the gcc compiler.
+ It uses the gcc backend to generate optimized code.
+ .
+ When using this package, tools must be invoked with an architecture prefix.
+ .
+ This is a dependency package.
+')`'dnl objcforhost
+
 ifenabled(`libobjc',`
 Package: libobjc`'OBJC_SO`'LS
 TARGET_PACKAGE`'dnl
@@ -2840,21 +2855,6 @@
  It uses the gcc backend to generate optimized code.
 ')')`'dnl for_each_arch

-Package: gfortran`'PV`'-for-host
-Architecture: ifdef(`TARGET',`TARGET',`any')
-TARGET_PACKAGE`'dnl
-Multi-Arch: same
-Depends: BASEDEP, gfortran`'PV`'${target:suffix} (>= ${gcc:SoftVersion}),
-  gcc`'PV`'-for-host (= ${gcc:Version}), ${misc:Depends}
-BUILT_USING`'dnl
-Description: GNU Fortran compiler for the host architecture
- This is the GNU Fortran compiler for the host architecture,
- which compiles Fortran on platforms supported by the gcc compiler.
- It uses the gcc backend to generate optimized code.
- .
- When using this package, tools must be invoked with an architecture prefix.
- .
- This is a dependency package.
 ifdef(`TARGET',`',`
 Package: gfortran`'PV`'-for-build
 Architecture: all
@@ -3089,6 +3089,24 @@
 ')`'dnl libx32gfortran
 ')`'dnl fortran

+ifenabled(`fortranforhost',`dnl
+Package: gfortran`'PV`'-for-host
+Architecture: ifdef(`TARGET',`TARGET',`any')
+TARGET_PACKAGE`'dnl
+Multi-Arch: same
+Depends: BASEDEP, gfortran`'PV`'${target:suffix} (>= ${gcc:SoftVersion}),
+  gcc`'PV`'-for-host (= ${gcc:Version}), ${misc:Depends}
+BUILT_USING`'dnl
+Description: GNU Fortran compiler for the host architecture
+ This is the GNU Fortran compiler for the host architecture,
+ which compiles Fortran on platforms supported by the gcc compiler.
+ It uses the gcc backend to generate optimized code.
+ .
+ When using this package, tools must be invoked with an architecture prefix.
+ .
+ This is a dependency package.
+')`'dnl fortranforhost
+
 ifenabled(`ggo',`
 ifenabled(`godev',`
 for_each_arch(`ifelse(index(` 'go_no_archs` ',` !'arch_deb` '),`-1',`
@@ -3107,21 +3125,6 @@
  backend to generate optimized code.
 ')')`'dnl for_each_arch

-Package: gccgo`'PV`'-for-host
-Architecture: ifdef(`TARGET',`TARGET',`any')
-TARGET_PACKAGE`'dnl
-Multi-Arch: same
-Depends: BASEDEP, gccgo`'PV`'${target:suffix} (>= ${gcc:SoftVersion}),
-  gcc`'PV`'-for-host (= ${gcc:Version}), ${misc:Depends}
-BUILT_USING`'dnl
-Description: GNU Go compiler for the host architecture
- This is the GNU Go compiler for the host architecture, which
- compiles Go on platforms supported by the gcc compiler. It uses the gcc
- backend to generate optimized code.
- .
- When using this package, tools must be invoked with an architecture prefix.
- .
- This is a dependency package.
 ifdef(`TARGET',`',`
 Package: gccgo`'PV`'-for-build
 Architecture: all
@@ -3362,6 +3365,24 @@
 ')`'dnl libx32go
 ')`'dnl ggo

+ifenabled(`godevforhost',`dnl
+Package: gccgo`'PV`'-for-host
+Architecture: ifdef(`TARGET',`TARGET',`any')
+TARGET_PACKAGE`'dnl
+Multi-Arch: same
+Depends: BASEDEP, gccgo`'PV`'${target:suffix} (>= ${gcc:SoftVersion}),
+  gcc`'PV`'-for-host (= ${gcc:Version}), ${misc:Depends}
+BUILT_USING`'dnl
+Description: GNU Go compiler for the host architecture
+ This is the GNU Go compiler for the host architecture, which
+ compiles Go on platforms supported by the gcc compiler. It uses the gcc
+ backend to generate optimized code.
+ .
+ When using this package, tools must be invoked with an architecture prefix.
+ .
+ This is a dependency package.
+')`'dnl godevforhost
+
 ifenabled(`c++',`
 ifenabled(`libcxx',`
 Package: libstdc++CXX_SO`'LS
@@ -3818,23 +3839,6 @@
  exceptions using the default zero-cost mechanism.
 ')')`'dnl for_each_arch

-Package: gnat`'PV`'-for-host
-Architecture: ifdef(`TARGET',`TARGET',`any')
-TARGET_PACKAGE`'dnl
-Multi-Arch: same
-Depends: BASEDEP, gnat`'PV`'${target:suffix} (>= ${gcc:SoftVersion}),
-  gcc`'PV`'-for-host (= ${gcc:Version}), ${misc:Depends}
-BUILT_USING`'dnl
-Description: GNU Ada compiler for the host architecture
- GNAT is a compiler for the Ada programming language. It produces optimized
- code on platforms supported by the GNU Compiler Collection (GCC).
- .
- This package provides the compiler, tools and runtime library that handles
- exceptions using the default zero-cost mechanism.
- .
- When using this package, tools must be invoked with an architecture prefix.
- .
- This is a dependency package.
 ifdef(`TARGET',`',`
 Package: gnat`'PV`'-for-build
 Architecture: all
@@ -3963,6 +3967,26 @@
 ')`'dnl gfdldoc
 ')`'dnl ada

+ifenabled(`adaforhost',`dnl
+Package: gnat`'PV`'-for-host
+Architecture: ifdef(`TARGET',`TARGET',`any')
+TARGET_PACKAGE`'dnl
+Multi-Arch: same
+Depends: BASEDEP, gnat`'PV`'${target:suffix} (>= ${gcc:SoftVersion}),
+  gcc`'PV`'-for-host (= ${gcc:Version}), ${misc:Depends}
+BUILT_USING`'dnl
+Description: GNU Ada compiler for the host architecture
+ GNAT is a compiler for the Ada programming language. It produces optimized
+ code on platforms supported by the GNU Compiler Collection (GCC).
+ .
+ This package provides the compiler, tools and runtime library that handles
+ exceptions using the default zero-cost mechanism.
+ .
+ When using this package, tools must be invoked with an architecture prefix.
+ .
+ This is a dependency package.
+')`'dnl adaforhost
+
 ifenabled(`d ',`dnl
 for_each_arch(`ifelse(index(` 'd_no_archs` ',` !'arch_deb` '),`-1',`
 Package: gdc`'PV`'arch_gnusuffix
@@ -3978,23 +4002,6 @@
  This compiler supports D language version 2.
 ')')`'dnl for_each_arch

-Package: gdc`'PV`'-for-host
-Architecture: ifdef(`TARGET',`TARGET',`any')
-TARGET_PACKAGE`'dnl
-Multi-Arch: same
-Depends: BASEDEP, gdc`'PV`'${target:suffix} (>= ${gcc:SoftVersion}),
-  gcc`'PV`'-for-host (= ${gcc:Version}), ${misc:Depends}
-BUILT_USING`'dnl
-Description: GNU D compiler (version 2) for the host architecture
- This is the GNU D compiler for the host architecture, which compiles D on
- platforms supported by gcc. It uses the gcc backend to generate optimised
- code.
- .
- This compiler supports D language version 2.
- .
- When using this package, tools must be invoked with an architecture prefix.
- .
- This is a dependency package.
 ifdef(`TARGET',`',`
 Package: gdc`'PV`'-for-build
 Architecture: all
@@ -4252,6 +4259,26 @@
 ')`'dnl libphobos
 ')`'dnl d

+ifenabled(`dforhost',`dnl
+Package: gdc`'PV`'-for-host
+Architecture: ifdef(`TARGET',`TARGET',`any')
+TARGET_PACKAGE`'dnl
+Multi-Arch: same
+Depends: BASEDEP, gdc`'PV`'${target:suffix} (>= ${gcc:SoftVersion}),
+  gcc`'PV`'-for-host (= ${gcc:Version}), ${misc:Depends}
+BUILT_USING`'dnl
+Description: GNU D compiler (version 2) for the host architecture
+ This is the GNU D compiler for the host architecture, which compiles D on
+ platforms supported by gcc. It uses the gcc backend to generate optimised
+ code.
+ .
+ This compiler supports D language version 2.
+ .
+ When using this package, tools must be invoked with an architecture prefix.
+ .
+ This is a dependency package.
+')`'dnl dforhost
+
 ifenabled(`m2 ',`dnl
 for_each_arch(`ifelse(index(` 'm2_no_archs` ',` !'arch_deb` '),`-1',`
 Package: gm2`'PV`'arch_gnusuffix
@@ -4265,21 +4292,6 @@
  backend to generate optimised code.
 ')')`'dnl for_each_arch

-Package: gm2`'PV`'-for-host
-Architecture: ifdef(`TARGET',`TARGET',`any')
-TARGET_PACKAGE`'dnl
-Multi-Arch: same
-Depends: BASEDEP, gm2`'PV`'${target:suffix} (>= ${gcc:SoftVersion}),
-  gcc`'PV`'-for-host (= ${gcc:Version}), ${misc:Depends}
-BUILT_USING`'dnl
-Description: GNU Modula-2 compiler for the host architecture
- This is the GNU Modula-2 compiler for the host architecture,
- which compiles Modula-2 on platforms supported by gcc.  It uses the gcc
- backend to generate optimised code.
- .
- When using this package, tools must be invoked with an architecture prefix.
- .
- This is a dependency package.
 ifdef(`TARGET',`',`
 Package: gm2`'PV`'-for-build
 Architecture: all
@@ -4506,6 +4518,24 @@
  Documentation for the GNU Modula-2 compiler in HTML and info `format'.
 ')`'dnl m2

+ifenabled(`m2forhost',`dnl
+Package: gm2`'PV`'-for-host
+Architecture: ifdef(`TARGET',`TARGET',`any')
+TARGET_PACKAGE`'dnl
+Multi-Arch: same
+Depends: BASEDEP, gm2`'PV`'${target:suffix} (>= ${gcc:SoftVersion}),
+  gcc`'PV`'-for-host (= ${gcc:Version}), ${misc:Depends}
+BUILT_USING`'dnl
+Description: GNU Modula-2 compiler for the host architecture
+ This is the GNU Modula-2 compiler for the host architecture,
+ which compiles Modula-2 on platforms supported by gcc.  It uses the gcc
+ backend to generate optimised code.
+ .
+ When using this package, tools must be invoked with an architecture prefix.
+ .
+ This is a dependency package.
+')`'dnl m2forhost
+
 ifenabled(`rust ',`
 for_each_arch(`ifelse(index(` 'rs_no_archs` ',` !'arch_deb` '),`-1',`
 Package: gccrs`'PV`'arch_gnusuffix
@@ -4525,28 +4555,6 @@
  and not usable yet for compiling real Rust programs !!!!!
 ')')`'dnl for_each_arch

-Package: gccrs`'PV`'-for-host
-Architecture: ifdef(`TARGET',`TARGET',`any')
-TARGET_PACKAGE`'dnl
-Multi-Arch: same
-Depends: BASEDEP, gccrs`'PV`'${target:suffix} (>= ${gcc:SoftVersion}),
-  gcc`'PV`'-for-host (= ${gcc:Version}), ${misc:Depends}
-BUILT_USING`'dnl
-Description: GNU Rust compiler for the host architecture
- !!!!! Please note, the compiler is in a very early stage
- and not usable yet for compiling real Rust programs !!!!!
- .
- gccrs is a full alternative implementation of the Rust
- language ontop of GCC with the goal to become fully
- upstream with the GNU toolchain.
- .
- !!!!! Please note, the compiler is in a very early stage
- and not usable yet for compiling real Rust programs !!!!!
- .
- When using this package, tools must be invoked with an architecture prefix.
- .
- This is a dependency package.
-
 Package: gccrs`'PV`'-for-build
 Architecture: all
 Multi-Arch: foreign
@@ -4584,6 +4592,30 @@
  and not usable yet for compiling real Rust programs !!!!!
 ')`'dnl rust

+ifenabled(`rustforhost',`dnl
+Package: gccrs`'PV`'-for-host
+Architecture: ifdef(`TARGET',`TARGET',`any')
+TARGET_PACKAGE`'dnl
+Multi-Arch: same
+Depends: BASEDEP, gccrs`'PV`'${target:suffix} (>= ${gcc:SoftVersion}),
+  gcc`'PV`'-for-host (= ${gcc:Version}), ${misc:Depends}
+BUILT_USING`'dnl
+Description: GNU Rust compiler for the host architecture
+ !!!!! Please note, the compiler is in a very early stage
+ and not usable yet for compiling real Rust programs !!!!!
+ .
+ gccrs is a full alternative implementation of the Rust
+ language ontop of GCC with the goal to become fully
+ upstream with the GNU toolchain.
+ .
+ !!!!! Please note, the compiler is in a very early stage
+ and not usable yet for compiling real Rust programs !!!!!
+ .
+ When using this package, tools must be invoked with an architecture prefix.
+ .
+ This is a dependency package.
+')`'dnl rustforhost
+
 ifdef(`TARGET',`',`dnl
 ifenabled(`libs',`
 #Package: gcc`'PV-soft-float
--- a/debian/rules.conf
+++ b/debian/rules.conf
@@ -739,6 +739,9 @@
 ifeq ($(with_gcclbase),yes)
   addons += gcclbase
 endif
+ifeq ($(LS),)
+  addons += cppforhost gccforhost c++forhost fortranforhost objcforhost objppforhost
+endif
 ifneq ($(DEB_STAGE),rtlibs)
   addons += cdev c++dev source multilib
   ifeq ($(build_type),build-native)
@@ -851,6 +854,9 @@
     addons += libdevphobos libdevn32phobos
     addons += $(if $(findstring amd64,$(biarchx32archs)),libdevx32phobos)
   endif
+  ifeq ($(LS),)
+    addons += dforhost
+  endif
 endif
 ifeq ($(with_go),yes)
   addons += ggo godev
@@ -858,6 +864,9 @@
     addons += libggo lib32ggo lib64ggo libn32ggo
     addons += $(if $(findstring amd64,$(biarchx32archs)),libx32ggo)
   endif
+  ifeq ($(LS),)
+    addons += godevforhost
+  endif
 endif
 ifeq ($(with_m2),yes)
   languages += m2
@@ -866,6 +875,9 @@
     addons += libgm2 # lib32gm2 lib64gm2 libn32gm2
     #addons += $(if $(findstring amd64,$(biarchx32archs)),libx32gm2)
   endif
+  ifeq ($(LS),)
+    addons += m2forhost
+  endif
 endif
 ifeq ($(with_rs),yes)
   languages += rust
@@ -874,6 +886,9 @@
   #  addons += libgrs # lib32gm2 lib64gm2 libn32gm2
   #  #addons += $(if $(findstring amd64,$(biarchx32archs)),libx32gm2)
   #endif
+  ifeq ($(LS),)
+    addons += rustforhost
+  endif
 endif
 ifeq ($(with_ada),yes)
   languages += ada
@@ -881,6 +896,9 @@
   ifeq ($(with_gnatsjlj),yes)
     addons += adasjlj
   endif
+  ifeq ($(LS),)
+    addons += adaforhost
+  endif
 endif
 
   ifneq ($(DEB_CROSS),yes)
--- a/debian/rules.d/binary-ada.mk
+++ b/debian/rules.d/binary-ada.mk
@@ -5,7 +5,7 @@
   $(lib_binaries) += libgnat
 endif

-arch_binaries := $(arch_binaries) ada-nat ada-host
+arch_binaries := $(arch_binaries) ada-nat
 ifeq ($(unprefixed_names),yes)
   arch_binaries := $(arch_binaries) ada
   indep_binaries := $(indep_binaries) ada-build
@@ -20,7 +20,6 @@
 p_glbase	= $(p_lbase)

 p_gnat_n = gnat-$(GNAT_VERSION)-$(subst _,-,$(TARGET_ALIAS))
-p_gnat_h = gnat-$(GNAT_VERSION)-for-host
 p_gnat_b = gnat-$(GNAT_VERSION)-for-build
 p_gnat	= gnat-$(GNAT_VERSION)
 p_gnatsjlj= gnat-$(GNAT_VERSION)-sjlj$(cross_bin_arch)
@@ -30,7 +29,6 @@

 d_gbase	= debian/$(p_gbase)
 d_gnat_n = debian/$(p_gnat_n)
-d_gnat_h = debian/$(p_gnat_h)
 d_gnat_b = debian/$(p_gnat_b)
 d_gnat	= debian/$(p_gnat)
 d_gnatsjlj	= debian/$(p_gnatsjlj)
@@ -167,15 +165,6 @@

 	trap '' 1 2 3 15; touch $@; mv $(install_stamp)-tmp $(install_stamp)

-$(binary_stamp)-ada-host: $(install_stamp)
-	dh_testdir
-	dh_testroot
-	mv $(install_stamp) $(install_stamp)-tmp
-	rm -rf $(d_gnat_h)
-	debian/dh_doclink -p$(p_gnat_h) $(p_xbase)
-	echo $(p_gnat_h) >> debian/arch_binaries
-	trap '' 1 2 3 15; touch $@; mv $(install_stamp)-tmp $(install_stamp)
-
 $(binary_stamp)-ada-build: $(install_stamp)
 	dh_testdir
 	dh_testroot
--- a/debian/rules.d/binary-cpp.mk
+++ b/debian/rules.d/binary-cpp.mk
@@ -1,5 +1,5 @@
 ifneq ($(DEB_STAGE),rtlibs)
-  arch_binaries  := $(arch_binaries) cpp-nat cpp-host
+  arch_binaries  := $(arch_binaries) cpp-nat
   ifeq ($(unprefixed_names),yes)
     arch_binaries  := $(arch_binaries) cpp
     indep_binaries := $(indep_binaries) cpp-build
@@ -13,12 +13,10 @@

 p_cpp  = cpp$(pkg_ver)
 p_cpp_n = cpp$(pkg_ver)-$(subst _,-,$(TARGET_ALIAS))
-p_cpp_h = cpp$(pkg_ver)-for-host
 p_cpp_d = cpp$(pkg_ver)-doc

 d_cpp	= debian/$(p_cpp)
 d_cpp_n = debian/$(p_cpp_n)
-d_cpp_h = debian/$(p_cpp_h)
 d_cpp_b = debian/$(p_cpp_b)
 d_cpp_d	= debian/$(p_cpp_d)

@@ -75,15 +73,6 @@

 	trap '' 1 2 3 15; touch $@; mv $(install_stamp)-tmp $(install_stamp)

-$(binary_stamp)-cpp-host: $(install_stamp)
-	dh_testdir
-	dh_testroot
-	mv $(install_stamp) $(install_stamp)-tmp
-	rm -rf $(d_cpp_h)
-	debian/dh_doclink -p$(p_cpp_h) $(p_xbase)
-	echo $(p_cpp_h) >> debian/arch_binaries
-	trap '' 1 2 3 15; touch $@; mv $(install_stamp)-tmp $(install_stamp)
-
 $(binary_stamp)-cpp-build: $(install_stamp)
 	dh_testdir
 	dh_testroot
--- a/debian/rules.d/binary-cxx.mk
+++ b/debian/rules.d/binary-cxx.mk
@@ -2,7 +2,7 @@
   ifneq (,$(filter yes, $(biarch64) $(biarch32) $(biarchn32) $(biarchx32)))
     arch_binaries  := $(arch_binaries) cxx-multi
   endif
-  arch_binaries  := $(arch_binaries) cxx-nat cxx-host
+  arch_binaries  := $(arch_binaries) cxx-nat
   ifeq ($(unprefixed_names),yes)
     arch_binaries  := $(arch_binaries) cxx
     indep_binaries := $(indep_binaries) cxx-build
@@ -11,12 +11,10 @@

 p_cxx = g++$(pkg_ver)
 p_cxx_n = g++$(pkg_ver)-$(subst _,-,$(TARGET_ALIAS))
-p_cxx_h = g++$(pkg_ver)-for-host
 p_cxx_b = g++$(pkg_ver)-for-build

 d_cxx = debian/$(p_cxx)
 d_cxx_n = debian/$(p_cxx_n)
-d_cxx_h = debian/$(p_cxx_h)
 d_cxx_b = debian/$(p_cxx_b)

 dirs_cxx_n = \
@@ -75,15 +73,6 @@

 	trap '' 1 2 3 15; touch $@; mv $(install_stamp)-tmp $(install_stamp)

-$(binary_stamp)-cxx-host: $(install_stamp)
-	dh_testdir
-	dh_testroot
-	mv $(install_stamp) $(install_stamp)-tmp
-	rm -rf $(d_cxx_h)
-	debian/dh_doclink -p$(p_cxx_h) $(p_xbase)
-	echo $(p_cxx_h) >> debian/arch_binaries
-	trap '' 1 2 3 15; touch $@; mv $(install_stamp)-tmp $(install_stamp)
-
 $(binary_stamp)-cxx-build: $(install_stamp)
 	dh_testdir
 	dh_testroot
--- a/debian/rules.d/binary-d.mk
+++ b/debian/rules.d/binary-d.mk
@@ -2,7 +2,7 @@
   ifneq (,$(filter yes, $(biarch64) $(biarch32) $(biarchn32)))
     arch_binaries  := $(arch_binaries) gdc-multi
   endif
-  arch_binaries := $(arch_binaries) gdc-nat gdc-host
+  arch_binaries := $(arch_binaries) gdc-nat
   ifeq ($(unprefixed_names),yes)
     arch_binaries := $(arch_binaries) gdc
     indep_binaries := $(indep_binaries) gdc-build
@@ -43,7 +43,6 @@
 endif

 p_gdc_n		= gdc$(pkg_ver)-$(subst _,-,$(TARGET_ALIAS))
-p_gdc_h		= gdc$(pkg_ver)-for-host
 p_gdc_b		= gdc$(pkg_ver)-for-build
 p_gdc           = gdc$(pkg_ver)
 p_gdc_m		= gdc$(pkg_ver)-multilib$(cross_bin_arch)
@@ -51,7 +50,6 @@
 p_libphobosdev  = libgphobos$(pkg_ver)-dev

 d_gdc_n		= debian/$(p_gdc_n)
-d_gdc_h		= debian/$(p_gdc_h)
 d_gdc_b		= debian/$(p_gdc_b)
 d_gdc           = debian/$(p_gdc)
 d_gdc_m		= debian/$(p_gdc_m)
@@ -139,15 +137,6 @@

 	trap '' 1 2 3 15; touch $@; mv $(install_stamp)-tmp $(install_stamp)

-$(binary_stamp)-gdc-host: $(install_stamp)
-	dh_testdir
-	dh_testroot
-	mv $(install_stamp) $(install_stamp)-tmp
-	rm -rf $(d_gdc_h)
-	debian/dh_doclink -p$(p_gdc_h) $(p_xbase)
-	echo $(p_gdc_h) >> debian/arch_binaries
-	trap '' 1 2 3 15; touch $@; mv $(install_stamp)-tmp $(install_stamp)
-
 $(binary_stamp)-gdc-build: $(install_stamp)
 	dh_testdir
 	dh_testroot
--- /dev/null
+++ b/debian/rules.d/binary-forhost.mk
@@ -0,0 +1,97 @@
+ifeq ($(with_cdev),yes)
+  arch_binaries := $(arch_binaries) cpp-host gcc-host
+endif
+ifeq ($(with_cxx),yes)
+  arch_binaries  := $(arch_binaries) cxx-host
+endif
+ifeq ($(with_fortran),yes)
+  arch_binaries  := $(arch_binaries) fdev-host
+endif
+ifeq ($(with_objc),yes)
+  arch_binaries  := $(arch_binaries) objc-host
+endif
+ifeq ($(with_objcxx),yes)
+  arch_binaries  := $(arch_binaries) objcxx-host
+endif
+ifeq ($(with_d),yes)
+  arch_binaries  := $(arch_binaries) gdc-host
+endif
+ifeq ($(with_go),yes)
+  arch_binaries  := $(arch_binaries) gccgo-host
+endif
+ifeq ($(with_m2),yes)
+  arch_binaries  := $(arch_binaries) gm2-host
+endif
+ifeq ($(with_rs),yes)
+  arch_binaries  := $(arch_binaries) grs-host
+endif
+ifeq ($(with_ada),yes)
+  arch_binaries  := $(arch_binaries) ada-host
+endif
+
+p_cpp_h = cpp$(pkg_ver)-for-host
+p_gcc_h = gcc$(pkg_ver)-for-host
+p_cxx_h = g++$(pkg_ver)-for-host
+p_g95_h = gfortran$(pkg_ver)-for-host
+p_objc_h = gobjc$(pkg_ver)-for-host
+p_objcx_h = gobjc++$(pkg_ver)-for-host
+p_gdc_h	= gdc$(pkg_ver)-for-host
+p_go_h	= gccgo$(pkg_ver)-for-host
+p_gm2_h	= gm2$(pkg_ver)-for-host
+p_grs_h = gccrs$(pkg_ver)-for-host
+p_gnat_h = gnat-$(GNAT_VERSION)-for-host
+
+d_cpp_h = debian/$(p_cpp_h)
+d_gcc_h = debian/$(p_gcc_h)
+d_cxx_h = debian/$(p_cxx_h)
+d_g95_h = debian/$(p_g95_h)
+d_objc_h = debian/$(p_objc_h)
+d_objcx_h = debian/$(p_objcx_h)
+d_gdc_h = debian/$(p_gdc_h)
+d_go_h  = debian/$(p_go_h)
+d_gm2_h	= debian/$(p_gm2_h)
+d_grs_h = debian/$(p_grs_h)
+d_gnat_h = debian/$(p_gnat_h)
+
+define do_for_host_package
+	dh_testdir
+	dh_testroot
+	mv $(install_stamp) $(install_stamp)-tmp
+	rm -rf debian/$(d_$(1)_h)
+	debian/dh_doclink -p$(p_$(1)_h) $(p_xbase)
+	echo $(p_$(1)_h) >> debian/arch_binaries
+	trap '' 1 2 3 15; touch $@; mv $(install_stamp)-tmp $(install_stamp)
+endef
+
+$(binary_stamp)-cpp-host: $(install_stamp)
+	$(call do_for_host_package,cpp)
+
+$(binary_stamp)-gcc-host: $(install_dependencies)
+	$(call do_for_host_package,gcc)
+
+$(binary_stamp)-cxx-host: $(install_stamp)
+	$(call do_for_host_package,cxx)
+
+$(binary_stamp)-fdev-host: $(install_stamp)
+	$(call do_for_host_package,g95)
+
+$(binary_stamp)-objc-host: $(install_stamp)
+	$(call do_for_host_package,objc)
+
+$(binary_stamp)-objcxx-host: $(install_stamp)
+	$(call do_for_host_package,objcx)
+
+$(binary_stamp)-gdc-host: $(install_stamp)
+	$(call do_for_host_package,gdc)
+
+$(binary_stamp)-gccgo-host: $(install_stamp)
+	$(call do_for_host_package,go)
+
+$(binary_stamp)-gm2-host: $(install_stamp)
+	$(call do_for_host_package,gm2)
+
+$(binary_stamp)-grs-host: $(install_stamp)
+	$(call do_for_host_package,grs)
+
+$(binary_stamp)-ada-host: $(install_stamp)
+	$(call do_for_host_package,gnat)
--- a/debian/rules.d/binary-fortran.mk
+++ b/debian/rules.d/binary-fortran.mk
@@ -33,7 +33,7 @@
   ifneq (,$(filter yes, $(biarch64) $(biarch32) $(biarchn32) $(biarchx32)))
     arch_binaries  := $(arch_binaries) fdev-multi
   endif
-  arch_binaries  := $(arch_binaries) fdev-nat fdev-host
+  arch_binaries  := $(arch_binaries) fdev-nat
   ifeq ($(unprefixed_names),yes)
     arch_binaries  := $(arch_binaries) fdev
     indep_binaries := $(indep_binaries) fdev-build
@@ -46,7 +46,6 @@
 endif

 p_g95_n = gfortran$(pkg_ver)-$(subst _,-,$(TARGET_ALIAS))
-p_g95_h = gfortran$(pkg_ver)-for-host
 p_g95_b = gfortran$(pkg_ver)-for-build
 p_g95	= gfortran$(pkg_ver)
 p_g95_m	= gfortran$(pkg_ver)-multilib$(cross_bin_arch)
@@ -54,7 +53,6 @@
 p_flib	= libgfortran$(FORTRAN_SONAME)$(cross_lib_arch)

 d_g95_n = debian/$(p_g95_n)
-d_g95_h = debian/$(p_g95_h)
 d_g95_b = debian/$(p_g95_b)
 d_g95	= debian/$(p_g95)
 d_g95_m	= debian/$(p_g95_m)
@@ -204,15 +202,6 @@

 	trap '' 1 2 3 15; touch $@; mv $(install_stamp)-tmp $(install_stamp)

-$(binary_stamp)-fdev-host: $(install_stamp)
-	dh_testdir
-	dh_testroot
-	mv $(install_stamp) $(install_stamp)-tmp
-	rm -rf $(d_g95_h)
-	debian/dh_doclink -p$(p_g95_h) $(p_xbase)
-	echo $(p_g95_h) >> debian/arch_binaries
-	trap '' 1 2 3 15; touch $@; mv $(install_stamp)-tmp $(install_stamp)
-
 $(binary_stamp)-fdev-build: $(install_stamp)
 	dh_testdir
 	dh_testroot
--- a/debian/rules.d/binary-gcc.mk
+++ b/debian/rules.d/binary-gcc.mk
@@ -6,7 +6,7 @@
     arch_binaries  := $(arch_binaries) gcc-plugindev
   endif

-  arch_binaries  := $(arch_binaries) gcc-nat gcc-host
+  arch_binaries  := $(arch_binaries) gcc-nat
   ifeq ($(unprefixed_names),yes)
     arch_binaries  := $(arch_binaries) gcc
     indep_binaries := $(indep_binaries) gcc-build
@@ -32,13 +32,11 @@

 p_gcc  = gcc$(pkg_ver)
 p_gcc_n = gcc$(pkg_ver)-$(subst _,-,$(TARGET_ALIAS))
-p_gcc_h = gcc$(pkg_ver)-for-host
 p_gcc_b = gcc$(pkg_ver)-for-build
 p_gcc_d = gcc$(pkg_ver)-doc

 d_gcc	= debian/$(p_gcc)
 d_gcc_n = debian/$(p_gcc_n)
-d_gcc_h = debian/$(p_gcc_h)
 d_gcc_b = debian/$(p_gcc_b)
 d_gcc_d	= debian/$(p_gcc_d)

@@ -153,15 +151,6 @@

 	trap '' 1 2 3 15; touch $@; mv $(install_stamp)-tmp $(install_stamp)

-$(binary_stamp)-gcc-host: $(install_dependencies)
-	dh_testdir
-	dh_testroot
-	mv $(install_stamp) $(install_stamp)-tmp
-	rm -rf $(d_gcc_h)
-	debian/dh_doclink -p$(p_gcc_h) $(p_xbase)
-	echo $(p_gcc_h) >> debian/arch_binaries
-	trap '' 1 2 3 15; touch $@; mv $(install_stamp)-tmp $(install_stamp)
-
 $(binary_stamp)-gcc-build: $(install_dependencies)
 	dh_testdir
 	dh_testroot
--- a/debian/rules.d/binary-go.mk
+++ b/debian/rules.d/binary-go.mk
@@ -30,7 +30,7 @@
 endif

 ifneq ($(DEB_STAGE),rtlibs)
-  arch_binaries  := $(arch_binaries) gccgo-nat gccgo-host
+  arch_binaries  := $(arch_binaries) gccgo-nat
   ifeq ($(unprefixed_names),yes)
     arch_binaries  := $(arch_binaries) gccgo
     indep_binaries := $(indep_binaries) gccgo-build
@@ -46,7 +46,6 @@
 endif

 p_go_n  = gccgo$(pkg_ver)-$(subst _,-,$(TARGET_ALIAS))
-p_go_h  = gccgo$(pkg_ver)-for-host
 p_go_b  = gccgo$(pkg_ver)-for-build
 p_go	= gccgo$(pkg_ver)
 p_go_m	= gccgo$(pkg_ver)-multilib$(cross_bin_arch)
@@ -54,7 +53,6 @@
 p_golib	= libgo$(GO_SONAME)$(cross_lib_arch)

 d_go_n  = debian/$(p_go_n)
-d_go_h  = debian/$(p_go_h)
 d_go_b  = debian/$(p_go_b)
 d_go	= debian/$(p_go)
 d_go_m	= debian/$(p_go_m)
@@ -310,15 +308,6 @@

 	trap '' 1 2 3 15; touch $@; mv $(install_stamp)-tmp $(install_stamp)

-$(binary_stamp)-gccgo-host: $(install_stamp)
-	dh_testdir
-	dh_testroot
-	mv $(install_stamp) $(install_stamp)-tmp
-	rm -rf $(d_go_h)
-	debian/dh_doclink -p$(p_go_h) $(p_xbase)
-	echo $(p_go_h) >> debian/arch_binaries
-	trap '' 1 2 3 15; touch $@; mv $(install_stamp)-tmp $(install_stamp)
-
 $(binary_stamp)-gccgo-build: $(install_stamp)
 	dh_testdir
 	dh_testroot
--- a/debian/rules.d/binary-m2.mk
+++ b/debian/rules.d/binary-m2.mk
@@ -4,7 +4,7 @@
     arch_binaries  := $(arch_binaries) gm2-multi
   endif
   endif
-  arch_binaries := $(arch_binaries) gm2-nat gm2-host
+  arch_binaries := $(arch_binaries) gm2-nat
   ifeq ($(unprefixed_names),yes)
     arch_binaries := $(arch_binaries) gm2
     indep_binaries := $(indep_binaries) gm2-build
@@ -51,7 +51,6 @@
 endif

 p_gm2_n		= gm2$(pkg_ver)-$(subst _,-,$(TARGET_ALIAS))
-p_gm2_h		= gm2$(pkg_ver)-for-host
 p_gm2_b		= gm2$(pkg_ver)-for-build
 p_gm2           = gm2$(pkg_ver)
 p_gm2_m		= gm2$(pkg_ver)-multilib$(cross_bin_arch)
@@ -60,7 +59,6 @@
 p_gm2d		= gm2$(pkg_ver)-doc

 d_gm2_n		= debian/$(p_gm2_n)
-d_gm2_h		= debian/$(p_gm2_h)
 d_gm2_b		= debian/$(p_gm2_b)
 d_gm2           = debian/$(p_gm2)
 d_gm2_m		= debian/$(p_gm2_m)
@@ -127,15 +125,6 @@

 	trap '' 1 2 3 15; touch $@; mv $(install_stamp)-tmp $(install_stamp)

-$(binary_stamp)-gm2-host: $(install_stamp)
-	dh_testdir
-	dh_testroot
-	mv $(install_stamp) $(install_stamp)-tmp
-	rm -rf $(d_gm2_h)
-	debian/dh_doclink -p$(p_gm2_h) $(p_xbase)
-	echo $(p_gm2_h) >> debian/arch_binaries
-	trap '' 1 2 3 15; touch $@; mv $(install_stamp)-tmp $(install_stamp)
-
 $(binary_stamp)-gm2-build: $(install_stamp)
 	dh_testdir
 	dh_testroot
--- a/debian/rules.d/binary-objc.mk
+++ b/debian/rules.d/binary-objc.mk
@@ -2,7 +2,7 @@
   ifneq (,$(filter yes, $(biarch64) $(biarch32) $(biarchn32) $(biarchx32)))
     arch_binaries  := $(arch_binaries) objc-multi
   endif
-  arch_binaries := $(arch_binaries) objc-nat objc-host
+  arch_binaries := $(arch_binaries) objc-nat
   ifeq ($(unprefixed_names),yes)
     arch_binaries := $(arch_binaries) objc
     indep_binaries := $(indep_binaries) objc-build
@@ -12,9 +12,6 @@
 p_objc_n = gobjc$(pkg_ver)-$(subst _,-,$(TARGET_ALIAS))
 d_objc_n = debian/$(p_objc_n)

-p_objc_h = gobjc$(pkg_ver)-for-host
-d_objc_h = debian/$(p_objc_h)
-
 p_objc_b = gobjc$(pkg_ver)-for-build
 d_objc_b = debian/$(p_objc_b)

@@ -61,15 +58,6 @@

 	trap '' 1 2 3 15; touch $@; mv $(install_stamp)-tmp $(install_stamp)

-$(binary_stamp)-objc-host: $(install_stamp)
-	dh_testdir
-	dh_testroot
-	mv $(install_stamp) $(install_stamp)-tmp
-	rm -rf $(d_objc_h)
-	debian/dh_doclink -p$(p_objc_h) $(p_xbase)
-	echo $(p_objc_h) >> debian/arch_binaries
-	trap '' 1 2 3 15; touch $@; mv $(install_stamp)-tmp $(install_stamp)
-
 $(binary_stamp)-objc-build: $(install_stamp)
 	dh_testdir
 	dh_testroot
--- a/debian/rules.d/binary-objcxx.mk
+++ b/debian/rules.d/binary-objcxx.mk
@@ -12,9 +12,6 @@
 p_objcx_n	= gobjc++$(pkg_ver)-$(subst _,-,$(TARGET_ALIAS))
 d_objcx_n	= debian/$(p_objcx_n)

-p_objcx_h	= gobjc++$(pkg_ver)-for-host
-d_objcx_h	= debian/$(p_objcx_h)
-
 p_objcx_b	= gobjc++$(pkg_ver)-for-build
 d_objcx_b	= debian/$(p_objcx_b)

@@ -61,15 +58,6 @@

 	trap '' 1 2 3 15; touch $@; mv $(install_stamp)-tmp $(install_stamp)

-$(binary_stamp)-objcxx-host: $(install_stamp)
-	dh_testdir
-	dh_testroot
-	mv $(install_stamp) $(install_stamp)-tmp
-	rm -rf $(d_objcx_h)
-	debian/dh_doclink -p$(p_objcx_h) $(p_xbase)
-	echo $(p_objcx_h) >> debian/arch_binaries
-	trap '' 1 2 3 15; touch $@; mv $(install_stamp)-tmp $(install_stamp)
-
 $(binary_stamp)-objcxx-build: $(install_stamp)
 	dh_testdir
 	dh_testroot
--- a/debian/rules.d/binary-rust.mk
+++ b/debian/rules.d/binary-rust.mk
@@ -4,7 +4,7 @@
   #  arch_binaries  := $(arch_binaries) grs-multi
   #endif
   endif
-  arch_binaries := $(arch_binaries) grs-nat grs-host
+  arch_binaries := $(arch_binaries) grs-nat
   ifeq ($(unprefixed_names),yes)
     arch_binaries := $(arch_binaries) grs
     indep_binaries := $(indep_binaries) grs-build
@@ -51,7 +51,6 @@
 endif

 p_grs_n		= gccrs$(pkg_ver)-$(subst _,-,$(TARGET_ALIAS))
-p_grs_h		= gccrs$(pkg_ver)-for-host
 p_grs_b		= gccrs$(pkg_ver)-for-build
 p_grs           = gccrs$(pkg_ver)
 p_grs_m		= gccrs$(pkg_ver)-multilib$(cross_bin_arch)
@@ -60,7 +59,6 @@
 p_grsd		= grs$(pkg_ver)-doc

 d_grs_n		= debian/$(p_grs_n)
-d_grs_h		= debian/$(p_grs_h)
 d_grs_b		= debian/$(p_grs_b)
 d_grs           = debian/$(p_grs)
 d_grs_m		= debian/$(p_grs_m)
@@ -124,15 +122,6 @@

 	trap '' 1 2 3 15; touch $@; mv $(install_stamp)-tmp $(install_stamp)

-$(binary_stamp)-grs-host: $(install_stamp)
-	dh_testdir
-	dh_testroot
-	mv $(install_stamp) $(install_stamp)-tmp
-	rm -rf $(d_grs_h)
-	debian/dh_doclink -p$(p_grs_h) $(p_xbase)
-	echo $(p_grs_h) >> debian/arch_binaries
-	trap '' 1 2 3 15; touch $@; mv $(install_stamp)-tmp $(install_stamp)
-
 $(binary_stamp)-grs-build: $(install_stamp)
 	dh_testdir
 	dh_testroot
--- a/debian/rules.defs
+++ b/debian/rules.defs
@@ -712,6 +712,13 @@
   with_dev := yes
 endif

+ifeq ($(LS),)
+  with_forhost := yes
+endif
+ifeq ($(single_package),yes)
+  with_forhost := disbaled for single package
+endif
+
 with_cpp := yes

 # set lang when built from a different source package.
--- a/debian/rules2
+++ b/debian/rules2
@@ -2437,6 +2437,10 @@
   include debian/rules.d/binary-hppa64.mk
 endif

+ifeq ($(with_forhost),yes)
+  include debian/rules.d/binary-forhost.mk
+endif
+
 endif # with_base_only
 endif # BACKPORT
 endif # ($(single_package),yes)
EOF
}
patch_gcc_wdotap() {
	if test "$ENABLE_MULTIARCH_GCC" = yes; then
		echo "applying patches for with_deps_on_target_arch_pkgs"
		drop_privs patch -p1 <<'EOF'
--- a/debian/control.m4
+++ b/debian/control.m4
@@ -131,12 +131,13 @@
  in a newer Ubuntu LTS release.
 ',`dnl regexp SRCNAME
 dnl default base package dependencies
-define(`BASEDEP', `gcc`'PV`'TS-base (= ${gcc:Version})')
-define(`SOFTBASEDEP', `gcc`'PV`'TS-base (>= ${gcc:SoftVersion})')
+define(`BASEPKG', `gcc`'PV`'ifdef(`CROSS_ARCH', ifelse(CROSS_ARCH, `all', `TS'))-base`'GCC_PORTS_BUILD')
+define(`BASEDEP', `BASEPKG (= ${gcc:Version})')
+define(`SOFTBASEDEP', `BASEPKG (>= ${gcc:SoftVersion})')

 ifdef(`TARGET',`
-define(`BASELDEP', `gcc`'PV`'ifelse(CROSS_ARCH,`all',`-cross')-base`'GCC_PORTS_BUILD (= ${gcc:Version})')
-define(`SOFTBASELDEP', `gcc`'PV`'ifelse(CROSS_ARCH, `all',`-cross')-base`'GCC_PORTS_BUILD (>= ${gcc:SoftVersion})')
+define(`BASELDEP', `BASEPKG (= ${gcc:Version})')
+define(`SOFTBASELDEP', `BASEPKG (>= ${gcc:SoftVersion})')
 ',`dnl
 define(`BASELDEP', `BASEDEP')
 define(`SOFTBASELDEP', `SOFTBASEDEP')
@@ -142,7 +143,7 @@
 ')

 ifenabled(`gccbase',`
-Package: gcc`'PV`'TS-base
+Package: BASEPKG
 Architecture: any
 Multi-Arch: same
 ifdef(`TARGET',`dnl',`Section: libs')
--- a/debian/rules.conf
+++ b/debian/rules.conf
@@ -683,7 +683,7 @@
 	-DTARGET=$(DEB_TARGET_ARCH) \
 	-DLIBUNWIND_BUILD_DEP="$(LIBUNWIND_BUILD_DEP)" \
 	-DLIBATOMIC_OPS_BUILD_DEP="$(LIBATOMIC_OPS_BUILD_DEP)"
-  ifeq ($(DEB_STAGE),rtlibs)
+  ifeq ($(LS),)
     ctrl_flags += -DCROSS_ARCH=$(DEB_TARGET_ARCH)
   endif
 else
@@ -1264,8 +1264,7 @@

 symbols-files: control-file
 ifeq ($(DEB_CROSS),yes)
-  ifneq ($(DEB_STAGE),rtlibs)
-	test -n "$(LS)"
+  ifneq ($(LS),)
 	set -e; \
 	for p in $$(dh_listpackages -i | grep '^lib'); do \
 	  p=$${p%$(LS)}; \
--- a/debian/rules.d/binary-base.mk
+++ b/debian/rules.d/binary-base.mk
@@ -23,7 +23,7 @@
 	dh_installchangelogs -p$(p_base)
 	dh_compress -p$(p_base)
 	dh_fixperms -p$(p_base)
-ifeq ($(DEB_STAGE)-$(DEB_CROSS),rtlibs-yes)
+ifeq ($(DEB_CROSS)-$(LS),yes-)
 	$(cross_gencontrol) dh_gencontrol -p$(p_base) -- -v$(DEB_VERSION) $(common_substvars)
 else
 	dh_gencontrol -p$(p_base) -- -v$(DEB_VERSION) $(common_substvars)
--- a/debian/rules.defs
+++ b/debian/rules.defs
@@ -182,9 +182,6 @@
   $(error Invalid architecure.)
 endif

-# Force this, people get confused about the default. See #760770.
-override with_deps_on_target_arch_pkgs :=
-
 # including unversiond symlinks for binaries
 #with_unversioned = yes

@@ -204,10 +201,16 @@
     # cross compiler, sets WITH_SYSROOT on it's own
     DEB_CROSS = yes
     build_type = build-cross
+    ifeq ($(with_deps_on_target_arch_pkgs),yes)
+      with_sysroot = /
+    endif
   else ifeq ($(FORCE_CROSS_LAYOUT),yes)
     # a native build with a cross layout
     DEB_CROSS = yes
     build_type = build-cross
+    ifeq ($(with_deps_on_target_arch_pkgs),yes)
+      with_sysroot = /
+    endif
   else
     # native build
     build_type = build-native
@@ -229,16 +232,24 @@
   TARGET := $(DEB_TARGET_ARCH)
   TP :=  $(subst _,-,$(DEB_TARGET_GNU_TYPE))-
   TS := -$(subst _,-,$(DEB_TARGET_ALIAS))
-  LS := -$(subst _,-,$(DEB_TARGET_ARCH))-cross
-  AQ :=

   cross_bin_arch := -$(subst _,-,$(DEB_TARGET_ALIAS))
-  cross_lib_arch := -$(subst _,-,$(DEB_TARGET_ARCH))-cross
   cmd_prefix := $(DEB_TARGET_GNU_TYPE)-

+  ifeq ($(with_deps_on_target_arch_pkgs),yes)
+    LS :=
+    cross_lib_arch :=
+    AQ := :$(TARGET)
+    lib_binaries := arch_binaries
+  else
+    LS := -$(subst _,-,$(DEB_TARGET_ARCH))-cross
+    cross_lib_arch := -$(subst _,-,$(DEB_TARGET_ARCH))-cross
+    AQ :=
+    lib_binaries := indep_binaries
+  endif
+
   TARGET_ALIAS := $(DEB_TARGET_ALIAS)

-  lib_binaries := indep_binaries
   cross_shlibdeps =  DEB_HOST_ARCH=$(TARGET) ARCH=$(DEB_TARGET_ARCH) MAKEFLAGS="CC=something"
   cross_gencontrol = DEB_HOST_ARCH=$(TARGET)
   cross_makeshlibs = DEB_HOST_ARCH=$(TARGET)
@@ -701,8 +712,8 @@

 # build -base packages
 with_gccbase := yes
-ifeq ($(build_type),build-cross)
-  ifneq ($(DEB_STAGE),rtlibs)
+ifeq ($(DEB_CROSS),yes)
+  ifneq ($(LS),)
     with_gcclbase := yes
   endif
 endif
@@ -2138,7 +2149,7 @@
   # FIXME: don't stop at the first shlibdeps failure ...
   ignshld = -
 endif
-ifeq ($(DEB_STAGE),rtlibs)
+ifeq ($(LS),)
   define cross_mangle_shlibs
   endef
   define cross_mangle_substvars
--- a/debian/rules.patch
+++ b/debian/rules.patch
@@ -188,7 +188,9 @@

 ifneq (,$(filter $(build_type), build-cross cross-build-cross))
   debian_patches += cross-fixes
-  debian_patches += cross-install-location
+  ifneq ($(LS),)
+    debian_patches += cross-install-location
+  endif
 endif

 debian_patches += hurd-multiarch
--- a/debian/rules2
+++ b/debian/rules2
@@ -854,9 +854,13 @@
 	--target=$(TARGET_ALIAS)

 ifeq ($(DEB_CROSS),yes)
-  CONFARGS += \
-	--program-prefix=$(TARGET_ALIAS)- \
-	--includedir=/$(PFL)/include
+  CONFARGS += --program-prefix=$(TARGET_ALIAS)-
+  ifeq ($(LS),)
+    # The build strips the sysroot (aka /) from the include gxx-include-dir.
+    CONFARGS += --with-gxx-include-dir='//$(PF)/include/c++/$(BASE_VERSION)'
+  else
+    CONFARGS += --includedir=/$(PFL)/include
+  endif
 endif

 ifeq ($(with_bootstrap),off)
@@ -979,19 +982,17 @@
 endif

 ifeq ($(DEB_CROSS),yes)
-ifneq ($(DEB_STAGE),rtlibs)
+ifneq ($(LS),)
   PFL		= $(PF)/$(DEB_TARGET_GNU_TYPE)
   RPF		= $(PF)/$(DEB_TARGET_GNU_TYPE)
 endif
 endif

-ifeq ($(with_multiarch_lib),yes)
-  ifeq ($(DEB_CROSS),yes)
-    libdir	= lib
-  else
-    libdir	= lib/$(DEB_TARGET_MULTIARCH)
-  endif
-else
+libdir		= lib/$(DEB_TARGET_MULTIARCH)
+ifeq ($(DEB_CROSS)-$(if $(LS),crosslayout),yes-crosslayout)
+  libdir	= lib
+endif
+ifneq ($(with_multiarch_lib),yes)
   libdir	= lib
 endif
 configured_libdir = lib
@@ -1015,7 +1015,9 @@
 gcc_subdir_name = gcc
 ifneq ($(single_package),yes)
   ifeq ($(DEB_CROSS),yes)
-    gcc_subdir_name = gcc-cross
+    ifneq ($(with_deps_on_target_arch_pkgs),yes)
+      gcc_subdir_name = gcc-cross
+    endif
   endif
 endif

@@ -1035,8 +1036,8 @@
 d_l= debian/$(p_l)
 d_d= debian/$(p_d)

-ifeq ($(DEB_CROSS),yes)
-  usr_lib = $(PFL)/lib
+ifeq ($(DEB_CROSS)-$(LS),yes-)
+  usr_lib = $(PF)/lib/$(DEB_TARGET_MULTIARCH)
 else
   usr_lib = $(PFL)/$(libdir)
 endif
@@ -1045,11 +1046,6 @@
 usr_libx32 = $(PFL)/libx32
 usr_lib64 = $(PFL)/lib64

-ifeq ($(DEB_STAGE)-$(DEB_CROSS),rtlibs-yes)
-  libdir	= lib/$(DEB_TARGET_MULTIARCH)
-  usr_lib	= $(PF)/lib/$(DEB_TARGET_MULTIARCH)
-endif
-
 gcc_lib_dir32 = $(gcc_lib_dir)/$(biarch32subdir)
 gcc_lib_dirn32 = $(gcc_lib_dir)/$(biarchn32subdir)
 gcc_lib_dirx32 = $(gcc_lib_dir)/$(biarchx32subdir)
@@ -2237,12 +2233,11 @@
 endif

 # if native or rtlibs build
-ifeq ($(if $(filter yes,$(DEB_CROSS)),$(if $(filter rtlibs,$(DEB_STAGE)),native,cross),native),native)
+ifneq ($(DEB_CROSS)-$(if $(LS),crosslayout),yes-crosslayout)
   p_base = gcc$(pkg_ver)-base
   p_lbase = $(p_base)
   p_xbase = gcc$(pkg_ver)-base
 else
-  # only triggered if DEB_CROSS set
   p_base = gcc$(pkg_ver)$(cross_bin_arch)-base
   p_lbase = gcc$(pkg_ver)-cross-base$(GCC_PORTS_BUILD)
   p_xbase = gcc$(pkg_ver)$(cross_bin_arch)-base
@@ -2641,7 +2636,7 @@

 	rm -rf $(d)/$(gcc_lib_dir)/include-fixed

-ifeq ($(DEB_STAGE)-$(DEB_CROSS),rtlibs-yes)
+ifeq ($(DEB_CROSS)-$(LS),yes-)
 	@echo configured_libdir=$(configured_libdir) / libdir=$(libdir) / usr_lib=$(usr_lib)
 	ls $(d)/$(PF)/$(TARGET_ALIAS)/lib
 	set -x; \
EOF
	fi
}
patch_gcc_14() {
	patch_gcc_limits_h_test
	patch_gcc_for_host_in_rtlibs
	patch_gcc_default_pie_everywhere
	patch_gcc_wdotap
}
buildenv_gcc_14() {
	echo "ignoring symbol differences #1085155"
	export DPKG_GENSYMBOLS_CHECK_LEVEL=0
}
patch_gcc_15() {
	patch_gcc_for_host_in_rtlibs
	patch_gcc_wdotap
}

add_automatic gdbm
buildenv_gdbm() {
	if dpkg-architecture "-a$1" -ignu-any-any; then
		export ac_cv_func_mmap_fixed_mapped=yes
	fi
}

patch_glib2_0() {
	dpkg-architecture "-a$HOST_ARCH" -ix32-any-any-any || return 0
	# https://github.com/mesonbuild/meson/issues/9845
	echo "working around wrong cc_can_run on x32"
	drop_privs tee -a debian/meson/libc-properties.ini >/dev/null <<EOF
needs_exe_wrapper=true
EOF
}

builddep_glibc() {
	test "$1" = "$HOST_ARCH"
	apt_get_install gettext file quilt autoconf gawk debhelper rdfind symlinks binutils bison netbase "gcc-$GCC_VER$HOST_ARCH_SUFFIX"
	if dpkg-architecture "-a$1" -ilinux-any; then
		apt_get_install linux-libc-dev
	elif dpkg-architecture "-a$1" -ihurd-any; then
		apt_get_install "gnumach-dev:$1" "hurd-headers-dev:$1" "mig$HOST_ARCH_SUFFIX"
	else
		echo "rebootstrap-error: unsupported kernel"
		exit 1
	fi
}
patch_glibc() {
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
-for i in `ls debian/tmp/usr/include/$(DEB_HOST_MULTIARCH)/sys`; do \
-	ln -sf ../$(DEB_HOST_MULTIARCH)/sys/$$i debian/$(1)/usr/include/sys/$$i; \
+mkdir -p debian/$(1)/usr/include; \
+for i in `ls debian/tmp/usr/include/$(DEB_HOST_MULTIARCH)`; do \
+	if test -d "debian/tmp/usr/include/$(DEB_HOST_MULTIARCH)/$$i" && ! test "$$i" = bits -o "$$i" = gnu; then \
+		mkdir -p "debian/$(1)/usr/include/$$i"; \
+		for j in `ls debian/tmp/usr/include/$(DEB_HOST_MULTIARCH)/$$i`; do \
+			ln -sf "../$(DEB_HOST_MULTIARCH)/$$i/$$j" "debian/$(1)/usr/include/$$i/$$j"; \
+		done; \
+	else \
+		ln -sf "$(DEB_HOST_MULTIARCH)/$$i" "debian/$(1)/usr/include/$$i"; \
+	fi; \
 done
 mkdir -p debian/$(1)/usr/include/finclude; \
 for i in `ls debian/tmp/usr/include/finclude/$(DEB_HOST_MULTIARCH)`; do \
@@ -270,15 +272,11 @@
 	    echo "/lib/$(DEB_HOST_GNU_TYPE)" >> $$conffile; \
 	    echo "/usr/lib/$(DEB_HOST_GNU_TYPE)" >> $$conffile; \
 	  fi; \
-	  mkdir -p $(debian-tmp)/usr/include/$(DEB_HOST_MULTIARCH); \
-	  mv $(debian-tmp)/usr/include/bits $(debian-tmp)/usr/include/$(DEB_HOST_MULTIARCH); \
-	  mv $(debian-tmp)/usr/include/gnu $(debian-tmp)/usr/include/$(DEB_HOST_MULTIARCH); \
-	  mv $(debian-tmp)/usr/include/sys $(debian-tmp)/usr/include/$(DEB_HOST_MULTIARCH); \
-	  mv $(debian-tmp)/usr/include/fpu_control.h $(debian-tmp)/usr/include/$(DEB_HOST_MULTIARCH); \
-	  mv $(debian-tmp)/usr/include/a.out.h $(debian-tmp)/usr/include/$(DEB_HOST_MULTIARCH); \
-	  mv $(debian-tmp)/usr/include/ieee754.h $(debian-tmp)/usr/include/$(DEB_HOST_MULTIARCH); \
+	  mkdir -p $(debian-tmp)/usr/include.tmp; \
+	  mv $(debian-tmp)/usr/include $(debian-tmp)/usr/include.tmp/$(DEB_HOST_MULTIARCH); \
+	  mv $(debian-tmp)/usr/include.tmp $(debian-tmp)/usr/include; \
 	  mkdir -p $(debian-tmp)/usr/include/finclude/$(DEB_HOST_MULTIARCH); \
-	  mv $(debian-tmp)/usr/include/finclude/math-vector-fortran.h $(debian-tmp)/usr/include/finclude/$(DEB_HOST_MULTIARCH); \
+	  mv $(debian-tmp)/usr/include/$(DEB_HOST_MULTIARCH)/finclude/math-vector-fortran.h $(debian-tmp)/usr/include/finclude/$(DEB_HOST_MULTIARCH); \
 	fi
 
 	ifeq ($(filter stage1,$(DEB_BUILD_PROFILES)),)
--- a/debian/sysdeps/hurd-i386.mk
+++ b/debian/sysdeps/hurd-i386.mk
@@ -18,9 +18,6 @@ endif
 define libc_extra_install
 mkdir -p $(debian-tmp)/lib
 ln -s ld.so.1 $(debian-tmp)/lib/ld.so
-mkdir -p $(debian-tmp)/usr/include/$(DEB_HOST_MULTIARCH)/mach
-mv $(debian-tmp)/usr/include/mach/i386 $(debian-tmp)/usr/include/$(DEB_HOST_MULTIARCH)/mach/
-ln -s ../$(DEB_HOST_MULTIARCH)/mach/i386 $(debian-tmp)/usr/include/mach/i386
 endef
 
 # FIXME: We are having runtime issues with ifunc...
EOF
}
buildenv_glibc() {
	export DEB_GCC_VERSION="-$GCC_VER"
	# glibc passes -Werror by default as it uses a fixed gcc version. We change that version.
	export DEB_CFLAGS_APPEND="${DEB_CFLAGS_APPEND:-} -Wno-error"
}

add_automatic gmp
buildenv_gmp() {
	if test "$GCC_VER" -ge 15; then
		echo "work around FTBFS with gcc-15 #1096730"
		export DEB_CFLAGS_APPEND="${DEB_CFLAGS_APPEND:-} -std=gnu17"
		export DEB_CFLAGS_FOR_BUILD_APPEND="${DEB_CFLAGS_FOR_BUILD_APPEND:-} -std=gnu17"
	fi
}

add_automatic gpm
buildenv_gpm() {
	if test "$GCC_VER" -ge 15; then
		echo "work around FTBFS with gcc-15 #1096759"
		export DEB_CFLAGS_APPEND="${DEB_CFLAGS_APPEND:-} -std=gnu17"
		export DEB_CFLAGS_FOR_BUILD_APPEND="${DEB_CFLAGS_FOR_BUILD_APPEND:-} -std=gnu17"
	fi
}
patch_gpm() {
	dpkg-architecture "-a$HOST_ARCH" -imusl-any-any || return 0
	echo "fixing missing include #1070124"
	drop_privs patch -p1 <<'EOF'
--- a/src/daemon/old_main.c
+++ b/src/daemon/old_main.c
@@ -19,6 +19,8 @@
  *
  ********/

+#include <string.h>                 /* str*              */
+#include <strings.h>                /* bzero             */
 #include <sys/socket.h>             /* UNIX              */
 #include <sys/un.h>                 /* SOCKET            */
 #include <fcntl.h>                  /* open              */
EOF
}

add_automatic grep
add_automatic groff

add_automatic gzip
buildenv_gzip() {
	dpkg-architecture "-a$1" -imusl-linux-any || return 0
	# this avoids replacing fseeko with a variant that is broken
	echo gl_cv_func_fflush_stdin exported
	export gl_cv_func_fflush_stdin=yes
}

add_automatic hostname
add_automatic icu
add_automatic isl
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

add_automatic libgc
buildenv_libgc() {
	if test "$1" = arc; then
		echo "ignoring symbol differences for arc #994211"
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

patch_libprelude() {
	echo "fix FTCBFS #1057733"
	drop_privs sed -i -e '/_FOR_BUILD/s/\<CFLAGS\>/&_FOR_BUILD/' src/libprelude-error/Makefile.am
}
buildenv_libprelude() {
	if dpkg-architecture "-a$1" -ignu-any-any; then
		echo "glibc does not return NULL for malloc(0)"
		export ac_cv_func_malloc_0_nonnull=yes
	fi
	if test "$(dpkg-architecture "-a$1" -qDEB_HOST_ARCH_BITS)" = 32; then
		echo "ignoring symbol differences on 32bit architectures due to #1085492"
		export DPKG_GENSYMBOLS_CHECK_LEVEL=0
	fi
}

add_automatic libpsl
add_automatic libpthread-stubs
add_automatic libsepol
add_automatic libsm
add_automatic libsodium
add_automatic libssh
add_automatic libssh2
add_automatic libsystemd-dummy
add_automatic libtasn1-6
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
	if dpkg-architecture "-a$1" -ignu-any-any; then
		echo "glibc does not prefer rwlock writers to readers"
		export gl_cv_pthread_rwlock_rdlock_prefer_writer=no
	fi
	echo "memchr and strstr generally work"
	export gl_cv_func_memchr_works=yes
	export gl_cv_func_strstr_works_always=yes
	export gl_cv_func_strstr_linear=yes
	if dpkg-architecture "-a$1" -imusl-any-any; then
		echo "setting malloc/realloc do not return 0"
		export ac_cv_func_malloc_0_nonnull=yes
		export ac_cv_func_realloc_0_nonnull=yes
	fi
}

add_automatic libusb
add_automatic libusb-1.0

add_automatic libverto
patch_libverto() {
	echo "demoting libglib2.0-dev dependency to libgio-2.0-dev #1082732"
	drop_privs sed -i -e 's/libglib2.0-dev/libgio-2.0-dev/' debian/control
}

add_automatic libx11
buildenv_libx11() {
	export xorg_cv_malloc0_returns_null=no
}

add_automatic libxau
add_automatic libxaw
add_automatic libxcb
add_automatic libxcrypt
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
patch_libxt() {
	echo "removing libglib2.0-dev dependency #1078927"
	drop_privs patch -p1 <<'EOF'
--- a/debian/control
+++ b/debian/control
@@ -12,7 +12,7 @@
  xutils-dev (>= 1:7.6+3),
  quilt,
 # for unit tests
- libglib2.0-dev (>= 2.16),
+ libglib2.0-dev (>= 2.16) <!nocheck>,
 # specs
  xmlto (>= 0.0.20),
  xorg-sgml-doctools (>= 1:1.10),
--- a/debian/rules
+++ b/debian/rules
@@ -17,7 +17,7 @@
 		--docdir=\$${datadir}/doc/libxt-dev \
 		--with-appdefaultdir=/etc/X11/app-defaults \
 		--with-xfile-search-path="/usr/lib/X11/%L/%T/%N%S:/usr/lib/X11/%l/%T/%N%S:/usr/lib/X11/%T/%N%S:/etc/X11/%L/%T/%N%C%S:/etc/X11/%l/%T/%N%C%S:/etc/X11/%T/%N%C%S:/etc/X11/%L/%T/%N%S:/etc/X11/%l/%T/%N%S:/etc/X11/%T/%N%S" \
-		--enable-unit-tests \
+		--$(if $(filter nocheck,$(DEB_BUILD_OPTIONS) $(DEB_BUILD_PROFILES)),dis,en)able-unit-tests \
 		--disable-silent-rules \
 		$(docflags) \
 		CFLAGS="$(CFLAGS)" \
EOF
}
buildenv_libxt() {
	export xorg_cv_malloc0_returns_null=no
}

add_automatic libzstd

patch_linux() {
	local kernel_arch
	kernel_arch=
	cat - debian/changelog <<EOF |
linux ($(dpkg-parsechangelog -SVersion)+rebootstrap1) sid; urgency=medium

  * Update for $HOST_ARCH

 -- rebootstrap <invalid@invalid>  $(dpkg-parsechangelog -SDate)

EOF
	drop_privs tee debian/changelog.new >/dev/null
	drop_privs mv debian/changelog.new debian/changelog
	case "$HOST_ARCH" in
		arc|csky|sparc)
			kernel_arch=$HOST_ARCH
		;;
		loong64) kernel_arch=loongarch ;;
		mipsr6el) kernel_arch=mips; ;;
		powerpcel) kernel_arch=powerpc; ;;
		# https://salsa.debian.org/kernel-team/linux/-/merge_requests/703/diffs
		riscv32) kernel_arch=riscv; ;;
		sh3) kernel_arch=sh; ;;
		*-linux-*)
			apt_get_install python3-toml
			kernel_arch=$(drop_privs python3 -c "print(next(d['name'] for d in __import__('toml.decoder').load(open('debian/config/defines.toml'))['kernelarch'] if any(e['name'] == '${HOST_ARCH#*-linux-}' for e in d['debianarch'])))")
		;;
	esac
	if test -n "$kernel_arch"; then
		echo "patching linux for $HOST_ARCH with kernel-arch $kernel_arch"
		drop_privs mkdir -p debian/config.local
		drop_privs tee debian/config.local/defines.toml >/dev/null <<EOF
[[kernelarch]]
name = '$kernel_arch'
  [[kernelarch.debianarch]]
  name = '$HOST_ARCH'
EOF
	fi
	apt_get_install kernel-wedge python3-jinja2 python3-dacite
	# intentionally exits 1 to avoid being called automatically. we are doing it wrong
	drop_privs sed -i -e '/^\s*exit 1$/d' debian/rules
	drop_privs ./debian/rules debian/rules.gen
}

add_automatic lmdb
add_automatic lz4
add_automatic man-db
add_automatic mawk
add_automatic mpclib3
add_automatic mpfr4

patch_musl() {
	echo "adding renameat2 to musl #1105007 https://git.musl-libc.org/cgit/musl/commit/include/stdio.h?id=05ce67fea99ca09cd4b6625cff7aec9cc222dd5a"
	drop_privs patch -p1 <<'EOF'
--- a/include/stdio.h
+++ b/include/stdio.h
@@ -158,6 +158,13 @@ char *ctermid(char *);
 #define L_ctermid 20
 #endif

+#if defined(_GNU_SOURCE)
+#define RENAME_NOREPLACE (1 << 0)
+#define RENAME_EXCHANGE  (1 << 1)
+#define RENAME_WHITEOUT  (1 << 2)
+
+int renameat2(int, const char *, int, const char *, unsigned);
+#endif

 #if defined(_XOPEN_SOURCE) || defined(_GNU_SOURCE) \
  || defined(_BSD_SOURCE)
EOF
}

builddep_ncurses() {
	if dpkg-architecture "-a$1" -ilinux-any; then
		assert_built gpm
		apt_get_install "libgpm-dev:$1"
	fi
	# g++-multilib dependency unsatisfiable
	apt_get_install debhelper pkg-config autoconf-dickey
	case "$ENABLE_MULTILIB:$1" in
		yes:amd64|yes:i386|yes:powerpc|yes:ppc64|yes:s390|yes:sparc)
			test "$1" = "$HOST_ARCH"
			apt_get_install "g++-$GCC_VER-multilib$HOST_ARCH_SUFFIX"
			# the unversioned gcc-multilib$HOST_ARCH_SUFFIX should contain the following link
			ln -sf "$(dpkg-architecture "-a$HOST_ARCH" -qDEB_HOST_MULTIARCH)/asm" /usr/include/asm
		;;
	esac
}

add_automatic nettle
add_automatic nghttp2
add_automatic npth
add_automatic nspr

add_automatic nss
patch_nss() {
	echo "support building without -Werror #1036211"
	drop_privs patch -p1 <<'EOF'
--- a/debian/rules
+++ b/debian/rules
@@ -74,8 +74,9 @@
 	$(NULL)

 # Disable -Werror on less mainline architectures.
-ifneq (,$(filter-out i386 x86_64 aarch64,$(DEB_HOST_GNU_CPU)))
+ifneq (,$(filter-out i386 x86_64 aarch64,$(DEB_HOST_GNU_CPU))$(filter -Wno-error,$(CFLAGS)))
 COMMON_MAKE_FLAGS += NSS_ENABLE_WERROR=0
+CFLAGS := $(filter-out -Wno-error,$(CFLAGS))
 endif

 NSS_TOOLS := \
EOF
}
buildenv_nss() {
	# nss tends to FTBFS with next gcc
	export DEB_CFLAGS_APPEND="${DEB_CFLAGS_APPEND:-} -Wno-error"
}

buildenv_openldap() {
	export ol_cv_pthread_select_yields=yes
	export ac_cv_func_memcmp_working=yes
}
patch_openldap() {
	echo "FTCBFS #1094386"
	drop_privs sed -i -e 's/AC_CHECK_PROGS/AC_CHECK_TOOLS/' configure.ac
}

add_automatic openssl
add_automatic p11-kit

builddep_pam() {
	echo "work around #1094853"
	apt_get_purge bison
	apt_get_build_dep "-a$1" --arch-only -P "$2" ./
}

add_automatic patch
add_automatic pcre2
add_automatic pcre3
add_automatic pkgconf
add_automatic popt

builddep_readline() {
	assert_built "ncurses"
	# gcc-multilib dependency unsatisfiable
	apt_get_install debhelper "libtinfo-dev:$1" "libncursesw5-dev:$1" mawk texinfo autotools-dev
	case "$ENABLE_MULTILIB:$1" in
		yes:amd64|yes:ppc64)
			test "$1" = "$HOST_ARCH"
			apt_get_install "gcc-$GCC_VER-multilib$HOST_ARCH_SUFFIX" "lib32ncurses-dev:$1"
			# the unversioned gcc-multilib$HOST_ARCH_SUFFIX should contain the following link
			ln -sf "$(dpkg-architecture "-a$1" -qDEB_HOST_MULTIARCH)/asm" /usr/include/asm
		;;
		yes:i386|yes:powerpc|yes:sparc|yes:s390)
			test "$1" = "$HOST_ARCH"
			apt_get_install "gcc-$GCC_VER-multilib$HOST_ARCH_SUFFIX" "lib64ncurses-dev:$1"
			# the unversioned gcc-multilib$HOST_ARCH_SUFFIX should contain the following link
			ln -sf "$(dpkg-architecture "-a$1" -qDEB_HOST_MULTIARCH)/asm" /usr/include/asm
		;;
	esac
}

add_automatic rtmpdump

add_automatic sed
patch_sed() {
	dpkg-architecture "-a$HOST_ARCH" -imusl-any-any || return 0
	echo "musl FTBFS #1010224"
	drop_privs sed -i -e '1ainclude /usr/share/dpkg/architecture.mk' debian/rules
	drop_privs sed -i -e 's/--without-included-regex/--with$(if $(filter musl,$(DEB_HOST_ARCH_LIBC)),,out)-included-regex/' debian/rules
}

add_automatic shadow
add_automatic slang2
add_automatic spdylay
add_automatic sqlite3
add_automatic sysvinit

add_automatic tar
buildenv_tar() {
	if dpkg-architecture "-a$1" -ignu-any-any; then
		echo "struct dirent contains working d_ino on glibc systems"
		export gl_cv_struct_dirent_d_ino=yes
	fi
	if ! dpkg-architecture "-a$1" -ilinux-any; then
		echo "forcing broken posix acl check to fail on non-linux #850668"
		export gl_cv_getxattr_with_posix_acls=no
	fi
	case "$1" in x32)
		echo "work around time64 inconsistency FTBFS to be fixed via #1030159"
		export DEB_CPPFLAGS_APPEND="${DEB_CPPFLAGS_APPEND:+$DEB_CPPFLAGS_APPEND }-D_LARGEFILE_SOURCE -D_FILE_OFFSET_BITS=64"
	esac
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
patch_xxhash() {
	echo "fix FTCBFS #1094015"
	drop_privs patch -p1 <<'EOF'
--- a/debian/rules
+++ b/debian/rules
@@ -4,6 +4,8 @@
 export DEB_BUILD_MAINT_OPTIONS = hardening=+all

 include /usr/share/dpkg/architecture.mk
+include /usr/share/dpkg/buildtools.mk
+export CC  # used in make install

 ifneq (,$(filter $(DEB_HOST_ARCH_CPU),i386 amd64))
 	export LIBXXH_DISPATCH=1
EOF
}

add_automatic xz-utils

builddep_zlib() {
	# gcc-multilib dependency unsatisfiable
	apt_get_install debhelper binutils dpkg-dev
}
patch_zlib() {
	echo "fix FTCBFS #1050995"
	drop_privs patch -p1 <<'EOF'
--- a/contrib/minizip/Makefile.am
+++ b/contrib/minizip/Makefile.am
@@ -39,7 +39,7 @@
 EXTRA_PROGRAMS = miniunzip minizip

 miniunzip_SOURCES = miniunz.c
-miniunzip_LDADD = libminizip.la
+miniunzip_LDADD = libminizip.la -lz

 minizip_SOURCES = minizip.c
 minizip_LDADD = libminizip.la -lz
--- a/debian/rules
+++ b/debian/rules
@@ -87,7 +77,8 @@

 	AR=$(AR) CC="$(DEB_HOST_GNU_TYPE)-gcc" CFLAGS="$(CFLAGS)" LDFLAGS="$(LDFLAGS)" uname=GNU ./configure --shared --prefix=/usr --libdir=\$${prefix}/lib/$(DEB_HOST_MULTIARCH)

-	cd contrib/minizip && autoreconf -fis && CFLAGS="$(CFLAGS)" LDFLAGS="$(LDFLAGS)" uname=GNU ./configure --prefix=/usr --libdir=\$${prefix}/lib/$(DEB_HOST_MULTIARCH)
+	cd contrib/minizip && autoreconf -fis
+	CFLAGS="$(CFLAGS)" LDFLAGS="$(LDFLAGS)" uname=GNU dh_auto_configure --sourcedirectory=contrib/minizip

 	touch $@

EOF
}

# choosing libatomic1 arbitrarily here, cause it never bumped soname
BUILD_GCC_MULTIARCH_VER=`apt-cache show --no-all-versions libatomic1 | sed 's/^Source: gcc-\([0-9.]*\)$/\1/;t;d'`
if test "$GCC_VER" != "$BUILD_GCC_MULTIARCH_VER"; then
	echo "host gcc version ($GCC_VER) and build gcc version ($BUILD_GCC_MULTIARCH_VER) mismatch. need different build gcc"
if dpkg --compare-versions "$GCC_VER" gt "$BUILD_GCC_MULTIARCH_VER"; then
	echo "deb [ arch=$(dpkg --print-architecture) ] $MIRROR experimental main" > /etc/apt/sources.list.d/tmp-experimental.list
	$APT_GET update
	$APT_GET -t experimental install g++ "g++-$GCC_VER"
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
		hook=$(get_hook buildenv "gcc-$GCC_VER") && "$hook" "$(dpkg --print-architecture)"
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
	assembler="$(dpkg-architecture "-a$HOST_ARCH" -qDEB_HOST_GNU_TYPE)-as"
	if ! command -v "$assembler" >/dev/null; then echo "$assembler missing in binutils package"; exit 1; fi
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
	if ! command -v hppa64-linux-gnu-as >/dev/null; then echo "hppa64-linux-gnu-as missing in binutils package"; exit 1; fi
	if ! drop_privs hppa64-linux-gnu-as -o test.o /dev/null; then echo "binutils-hppa64 fail to execute"; exit 1; fi
	if ! test -f test.o; then echo "binutils-hppa64 fail to create object"; exit 1; fi
	check_arch test.o hppa64
	touch "$REPODIR/stamps/cross-binutils-hppa64"
	cd ..
	drop_privs rm -Rf binutils-hppa64-linux-gnu
	progress_mark "cross binutils-hppa64"
fi

if ! dpkg-architecture "-a$HOST_ARCH" -ilinux-any; then
	:
elif test -f "$REPODIR/stamps/linux_1"; then
	echo "skipping rebuild of linux-libc-dev"
else
	REBUILD_LINUX=
	apt_get_install linux-libc-dev
	if ! test -h "/usr/include/$(dpkg-architecture "-a$HOST_ARCH" -qDEB_HOST_MULTIARCH)/asm/unistd.h"; then
		REBUILD_LINUX=missing
	fi
	if test -n "$REBUILD_LINUX"; then
		cross_build_setup linux
		linux_libc_dev_profiles=nocheck,pkg.linux.nokernel,pkg.linux.notools,pkg.linux.quick
		apt_get_build_dep --indep-only "-P$linux_libc_dev_profiles" ./
		drop_privs KBUILD_VERBOSE=1 dpkg-buildpackage -A "-P$linux_libc_dev_profiles" -uc -us
		cd ..
		ls -l
		reprepro include rebootstrap-native ./*.changes
		$APT_GET update
		apt_get_install linux-libc-dev
		cd ..
		drop_privs rm -Rf linux
	fi
	if test "$ENABLE_MULTIARCH_GCC" = no; then
		cd /tmp/buildd
		drop_privs mkdir linux
		cd linux
		drop_privs apt-get download linux-libc-dev
		drop_privs dpkg-cross -a "$HOST_ARCH" -M -b ./linux-libc-dev_*_all.deb
		pickup_additional_packages ./linux-libc-dev-*-cross_*_all.deb
		cd ..
		drop_privs rm -Rf linux
	fi
	touch "$REPODIR/stamps/linux_1"
	progress_mark "linux-libc-dev build"
fi

if dpkg-architecture "-a$HOST_ARCH" -ihurd-any; then
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
	apt_get_install debhelper gawk patchutils bison flex lsb-release quilt libtool $GCC_AUTOCONF zlib1g-dev libmpc-dev libmpfr-dev libgmp-dev systemtap-sdt-dev sharutils "binutils$HOST_ARCH_SUFFIX" time
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
		hook=$(get_hook buildenv "gcc-$GCC_VER") && "$hook" "$HOST_ARCH"
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
	if ! command -v "$compiler" >/dev/null; then echo "$compiler missing in stage1 gcc package"; exit 1; fi
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

if dpkg-architecture "-a$HOST_ARCH" -ihurd-any; then
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

if dpkg-architecture "-a$HOST_ARCH" -ihurd-any; then
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

case "$HOST_ARCH" in
	musl-linux-*) LIBC_NAME=musl ;;
	*) LIBC_NAME=glibc ;;
esac
if test -f "$REPODIR/stamps/${LIBC_NAME}_2"; then
	echo "skipping rebuild of $LIBC_NAME stage2"
else
	cross_build_setup "$LIBC_NAME" "${LIBC_NAME}_2"
	if dpkg-architecture "-a$HOST_ARCH" -ignu-any-any; then
		"$(get_hook builddep glibc)" "$HOST_ARCH" stage2
	else
		apt_get_build_dep "-a$HOST_ARCH" --arch-only ./
	fi
	(
		profiles=$(join_words , $DEFAULT_PROFILES)
		if dpkg-architecture "-a$HOST_ARCH" -ignu-any-any; then
			profiles="$profiles,stage2"
			test "$ENABLE_MULTILIB" != yes && profiles="$profiles,nobiarch"
			buildenv_glibc
		fi
		# tell unmet build depends
		drop_privs dpkg-checkbuilddeps -B "-a$HOST_ARCH" "-P$profiles" || :
		drop_privs_exec dpkg-buildpackage -B -uc -us "-a$HOST_ARCH" -d "-P$profiles" || buildpackage_failed "$?"
	)
	cd ..
	ls -l
	if dpkg-architecture "-a$HOST_ARCH" -imusl-any-any; then
		pickup_packages *.changes
		apt_get_install ./musl*.deb
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
			apt_get_install "linux-libc-dev-$HOST_ARCH-cross"
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
	apt_get_install debhelper gawk patchutils bison flex lsb-release quilt libtool $GCC_AUTOCONF zlib1g-dev libmpc-dev libmpfr-dev libgmp-dev dejagnu systemtap-sdt-dev sharutils "binutils$HOST_ARCH_SUFFIX" time
	if test "$HOST_ARCH" = hppa; then
		apt_get_install binutils-hppa64-linux-gnu
	fi
	if test "$ENABLE_MULTIARCH_GCC" = yes; then
		apt_get_install "libc-dev:$HOST_ARCH" $(echo $MULTILIB_NAMES | sed "s/\(\S\+\)/libc6-dev-\1:$HOST_ARCH/g")
	else
		if dpkg-architecture "-a$HOST_ARCH" -ignu-any-any; then
			apt_get_install "libc6-dev-$HOST_ARCH-cross" $(echo $MULTILIB_NAMES | sed "s/\(\S\+\)/libc6-dev-\1-$HOST_ARCH-cross/g")
		elif dpkg-architecture "-a$HOST_ARCH" -imusl-any-any; then
			apt_get_install "musl-dev-$HOST_ARCH-cross"
		fi
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
		hook=$(get_hook buildenv "gcc-$GCC_VER") && "$hook" "$HOST_ARCH"
		drop_privs dpkg-buildpackage -d -T control
		drop_privs dpkg-buildpackage -d -T clean
		dpkg-checkbuilddeps || : # tell unmet build depends again after rewriting control
		drop_privs_exec dpkg-buildpackage -d -b -uc -us
	)
	cd ..
	ls -l
	pickup_packages *.changes
	# avoid file conflicts between differently staged M-A:same packages
	apt_get_remove "gcc-$GCC_VER-base:$HOST_ARCH"
	drop_privs rm -fv gcc-*-plugin-*.deb gcj-*.deb gdc-*.deb ./*objc*.deb ./*-dbg_*.deb
	dpkg -i *.deb
	compiler="$(dpkg-architecture "-a$HOST_ARCH" -qDEB_HOST_GNU_TYPE)-gcc-$GCC_VER"
	if ! command -v "$compiler" >/dev/null; then echo "$compiler missing in stage3 gcc package"; exit 1; fi
	if ! drop_privs "$compiler" -x c -c /dev/null -o test.o; then echo "stage3 gcc fails to execute"; exit 1; fi
	if ! test -f test.o; then echo "stage3 gcc fails to create binaries"; exit 1; fi
	check_arch test.o "$HOST_ARCH"
	mkdir -p "/usr/include/$(dpkg-architecture "-a$HOST_ARCH" -qDEB_HOST_MULTIARCH)"
	touch "/usr/include/$(dpkg-architecture "-a$HOST_ARCH" -qDEB_HOST_MULTIARCH)/include_path_test_header.h"
	preproc="$(dpkg-architecture "-a$HOST_ARCH" -qDEB_HOST_GNU_TYPE)-cpp-$GCC_VER"
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
	apt_get_install debhelper gawk patchutils bison flex lsb-release quilt libtool $GCC_AUTOCONF zlib1g-dev libmpc-dev libmpfr-dev libgmp-dev dejagnu systemtap-sdt-dev sharutils "binutils$HOST_ARCH_SUFFIX" "libc-dev:$HOST_ARCH" time
	if test "$HOST_ARCH" = hppa; then
		apt_get_install binutils-hppa64-linux-gnu
	fi
	if test "$ENABLE_MULTILIB" = yes -a -n "$MULTILIB_NAMES"; then
		apt_get_install $(echo "$MULTILIB_NAMES" | sed 's/\(\S\+\)/libc6-dev-\1-'"$HOST_ARCH-cross libc6-dev-\\1:$HOST_ARCH/g")
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
		hook=$(get_hook buildenv "gcc-$GCC_VER") && "$hook" "$HOST_ARCH"
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
add_need blt # by pythonX.Y
add_need bsdmainutils # for man-db
add_need bzip2 # by gnupg2, perl
add_need db-defaults # by perl, python3.X
add_need expat # by unbound
add_need file # by gcc-6, for debhelper
add_need flex # by pam
add_need fribidi # by newt
add_need gdbm # by perl, python3.X
add_need gnutls28 # by gnupg2
dpkg-architecture "-a$HOST_ARCH" -ilinux-any && add_need gpm # by ncurses
add_need groff # for man-db
dpkg-architecture "-a$HOST_ARCH" -ilinux-any && add_need kmod # by systemd
add_need icu # by libxml2
add_need isl # by gcc-VER
add_need jansson # by binutils
add_need krb5 # by audit
add_need libassuan # by gnupg2
dpkg-architecture "-a$HOST_ARCH" -ilinux-any && add_need libcap2 # by systemd
add_need libdebian-installer # by cdebconf
add_need libevent # by unbound
add_need libgcrypt20 # by gnupg2, libprelude
add_need libgpg-error # by gnupg2
add_need libidn2 # by gnutls28
add_need libksba # by gnupg2
dpkg-architecture "-a$HOST_ARCH" -ilinux-any && add_need libsepol # by libselinux
if dpkg-architecture "-a$HOST_ARCH" -ihurd-any; then
	add_need libsystemd-dummy # by nghttp2
fi
add_need libtasn1-6 # by gnutls28
add_need libtextwrap # by cdebconf
add_need libunistring # by gnutls28
add_need libxcrypt # by cyrus-sasl2, pam, shadow, systemd
add_need libxrender # by cairo
add_need libzstd # by systemd
add_need lz4 # by systemd
add_need man-db # for debhelper
add_need mawk # for base-files (alternatively: gawk)
add_need mpclib3 # by gcc-VER
add_need mpfr4 # by gcc-VER
add_need nettle # by unbound, gnutls28
add_need npth # by gnupg2
add_need openssl # by cyrus-sasl2
add_need p11-kit # by gnutls28
add_need patch # for dpkg-dev
add_need pcre2 # by libselinux
add_need pkgconf # by gnupg2
add_need popt # by newt
add_need slang2 # by cdebconf, newt
add_need sqlite3 # by python3.X
add_need tcl8.6 # by newt
add_need tcltk-defaults # by python3.X
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
					missing=${missing%":$HOST_ARCH"} # skip architecture
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
# needed libffi

automatically_cross_build_packages

cross_build ncurses
mark_built ncurses
# needed by bash, bsdmainutils, dpkg, readline, slang2

automatically_cross_build_packages

cross_build readline
mark_built readline
# needed by gnupg2, libxml2

automatically_cross_build_packages

if dpkg-architecture "-a$HOST_ARCH" -ilinux-any; then
	assert_built "libsepol pcre2"
	cross_build libselinux "nopython noruby" libselinux_1
	mark_built libselinux
# needed by coreutils, dpkg, findutils, glibc, sed, tar, util-linux

automatically_cross_build_packages
fi # $HOST_ARCH matches linux-any

cross_build brotli nopython brotli_1
mark_built brotli
# needed by curl, freetype

automatically_cross_build_packages

dpkg-architecture "-a$HOST_ARCH" -ilinux-any && assert_built libselinux
assert_built "ncurses zlib"
cross_build util-linux "stage1 pkg.util-linux.noverity" util-linux_1
mark_built util-linux
# essential, needed by e2fsprogs

automatically_cross_build_packages

cross_build db5.3 "pkg.db5.3.notcl nojava" db5.3_1
mark_built db5.3
# needed by perl, python3.X, needed for db-defaults

automatically_cross_build_packages

cross_build libxml2 nopython libxml2_1
mark_built libxml2
# needed by nghttp2

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

assert_built "db-defaults db5.3 pam sqlite3 openssl"
cross_build cyrus-sasl2 "pkg.cyrus-sasl2.nogssapi pkg.cyrus-sasl2.noldap pkg.cyrus-sasl2.nosql" cyrus-sask2_1
mark_built cyrus-sasl2
# needed by openldap

automatically_cross_build_packages

assert_built "libevent expat nettle"
dpkg-architecture "-a$HOST_ARCH" -ilinux-any || assert_built libbsd
cross_build unbound pkg.unbound.libonly unbound_1
mark_built unbound
# needed by gnutls28

automatically_cross_build_packages

assert_built "gmp libidn2 p11-kit libtasn1-6 unbound libunistring nettle"
cross_build gnutls28 noguile gnutls28_1
mark_built gnutls28
# needed by libprelude, openldap, curl

automatically_cross_build_packages

assert_built "gnutls28 cyrus-sasl2"
cross_build openldap pkg.openldap.noslapd openldap_1
mark_built openldap
# needed by curl

automatically_cross_build_packages

if dpkg-architecture "-a$HOST_ARCH" -ilinux-any; then
if apt-cache showsrc man-db systemd | grep -q "^Build-Depends:.*libseccomp-dev[^,]*[[ ]${HOST_ARCH}[] ]"; then
	cross_build libseccomp nopython libseccomp_1
	mark_built libseccomp
# needed by man-db, systemd

	automatically_cross_build_packages
fi


assert_built "libcap2 pam libselinux acl xz-utils libgcrypt20 kmod util-linux libzstd"
if apt-cache showsrc systemd | grep -q "^Build-Depends:.*libseccomp-dev[^,]*[[ ]$HOST_ARCH[] ]"; then
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

cross_build libxt
mark_built libxt
# temporarily manual for #1078927

automatically_cross_build_packages

assert_built "elfutils libffi"
dpkg-architecture "-a$HOST_ARCH" -ilinux-any && assert_built "util-linux libselinux"
cross_build glib2.0 "nogir pkg.glib2.0.nosysprof" glib2.0_1
mark_built glib2.0
# needed by libverto

automatically_cross_build_packages

cross_build libverto
mark_built libverto
# needed by krb5

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

dpkg-architecture "-a$HOST_ARCH" -ilinux-any && assert_built "audit libcap-ng libselinux systemd"
assert_built "ncurses zlib"
cross_build util-linux "pkg.util-linux.noverity"
# essential

automatically_cross_build_packages

cross_build newt nopython newt_1
mark_built newt
# needed by cdebconf

automatically_cross_build_packages

cross_build cdebconf pkg.cdebconf.nogtk cdebconf_1
mark_built cdebconf
# needed by base-passwd

automatically_cross_build_packages

cross_build make-dfsg noguile make-dfsg_1
mark_built make-dfsg
# needed by build-essential

automatically_cross_build_packages

if test -f "$REPODIR/stamps/binutils_2"; then
	echo "skipping cross rebuild of binutils"
else
	cross_build_setup binutils binutils_2
	apt_get_build_dep "-a$HOST_ARCH" --arch-only -P nocheck,pkg.binutils.nojava ./
	check_binNMU
	DEB_BUILD_OPTIONS="$DEB_BUILD_OPTIONS nocross nomult" drop_privs dpkg-buildpackage "-a$HOST_ARCH" -Pnocheck,pkg.binutils.nojava -B -uc -us
	rm -Rf /tmp/nodebugedit
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

cross_build gnupg2 pkg.gnupg2.gpgvonly gnupg2_1
mark_built gnupg2
# needed for apt

automatically_cross_build_packages

assert_built "$need_packages"

echo "checking installability of build-essential with dose"
apt_get_install botch
package_list=$(mktemp -t packages.XXXXXXXXXX)
grep-dctrl --exact --field Architecture '(' "$HOST_ARCH" --or all ')' /var/lib/apt/lists/*_Packages > "$package_list"
botch-distcheck-more-problems "--deb-native-arch=$HOST_ARCH" --successes --failures --explain --checkonly "build-essential:$HOST_ARCH" "--bg=deb://$package_list" "--fg=deb://$package_list" || :
rm -f "$package_list"
