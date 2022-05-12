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
APT_GET="apt-get --no-install-recommends -y -o Debug::pkgProblemResolver=true -o Debug::pkgDepCache::Marker=1 -o Debug::pkgDepCache::AutoInstall=1 -o Acquire::Languages=none"
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
			"arc:ELF 32-bit LSB relocatable, *unknown arch 0xc3* version 1 (SYSV)"*|"arc:ELF 32-bit LSB relocatable, Synopsys ARCv2/HS3x/HS4x cores, version 1 (SYSV)"*)
				return 0
			;;
			"csky:ELF 32-bit LSB relocatable, *unknown arch 0xfc* version 1 (SYSV)"*|"csky:ELF 32-bit LSB relocatable, C-SKY processor family, version 1 (SYSV)"*)
				return 0
			;;
			"loongarch64:ELF 64-bit LSB relocatable, LoongArch, version 1 (SYSV)"*)
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

echo "fixing debhelper dh_installchangelogs #1009844"
sed -i -e '/error.*does not exist/d' /usr/bin/dh_installalternatives

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

cat <<EOF >> /usr/share/dpkg/cputable
csky		csky		csky		32	little
loongarch64	loongarch64	loongarch64	64	little
EOF

if test -z "$HOST_ARCH" || ! dpkg-architecture "-a$HOST_ARCH"; then
	echo "architecture $HOST_ARCH unknown to dpkg"
	exit 1
fi

# ensure that the rebootstrap list comes first
test -f /etc/apt/sources.list && mv -v /etc/apt/sources.list /etc/apt/sources.list.d/local.list
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
	echo "debian_patches += limits-h-test" | drop_privs tee -a debian/rules.patch >/dev/null
}
patch_gcc_unapplicable_ada() {
	echo "fix patch application failure #993205"
	drop_privs sed -i -e /ada-armel-libatomic/d debian/rules.patch
}
patch_gcc_arc_multilib_multiarch() {
        if test "$HOST_ARCH" = arc; then
                echo "patching arc gcc: disable multilib #989453"
                drop_privs patch -p1 <<'EOF'
diff --git a/debian/rules2 b/debian/rules2
index 750c03f..880a63e 100644
--- a/debian/rules2
+++ b/debian/rules2
@@ -466,6 +466,10 @@ ifneq (,$(findstring arm-vfp,$(DEB_TARGET_GNU_CPU)))
   CONFARGS += --with-fpu=vfp
 endif

+ifneq (,$(findstring arc-linux,$(DEB_TARGET_GNU_TYPE)))
+  CONFARGS += --disable-multilib
+endif
+
 ifneq (,$(findstring arm, $(DEB_TARGET_GNU_CPU)))
   ifeq ($(multilib),yes)
     CONFARGS += --enable-multilib
EOF
        fi
}
patch_gcc_rtlibs_libatomic() {
	test "$ENABLE_MULTIARCH_GCC" = no || return 0
	echo "do build libatomic rtlibs #1009286"
	drop_privs sed -i -e '/with_libatomic := disabled for rtlibs stage/d' debian/rules.defs
}
patch_gcc_cross_fixes_diff() {
	echo "fix application of cross-fixes.diff #1010330"
	drop_privs patch -p1 <<'EOF'
--- a/debian/patches/cross-fixes.diff
+++ b/debian/patches/cross-fixes.diff
@@ -9,20 +9,16 @@

 --- a/src/libgcc/config/ia64/fde-glibc.c
 +++ b/src/libgcc/config/ia64/fde-glibc.c
-@@ -28,6 +28,7 @@
+@@ -28,8 +28,8 @@
  #ifndef _GNU_SOURCE
  #define _GNU_SOURCE 1
  #endif
 +#ifndef inhibit_libc
  #include "config.h"
+-#ifndef inhibit_libc
  #include <stddef.h>
  #include <stdlib.h>
-@@ -159,3 +160,5 @@ _Unwind_FindTableEntry (void *pc, unw_wo
- 
-   return data.ret;
- }
-+
-+#endif
+ #include <link.h>
 --- a/src/libgcc/config/ia64/unwind-ia64.c
 +++ b/src/libgcc/config/ia64/unwind-ia64.c
 @@ -26,6 +26,7 @@
EOF
}
patch_gcc_wdotap() {
	if test "$ENABLE_MULTIARCH_GCC" = yes; then
		echo "applying patches for with_deps_on_target_arch_pkgs"
		drop_privs rm -Rf .pc
		drop_privs QUILT_PATCHES="/usr/share/cross-gcc/patches/gcc-$GCC_VER" quilt push -a
		drop_privs rm -Rf .pc
	fi
}
patch_gcc_11() {
	# do build common libraries
	drop_privs sed -i -e 's/^\s*#\?\(with_common_libs\s*:\?=\).*/\1yes/' debian/rules.defs
	patch_gcc_limits_h_test
	patch_gcc_default_pie_everywhere
	patch_gcc_arc_multilib_multiarch
	patch_gcc_wdotap
}
patch_gcc_12() {
	patch_gcc_limits_h_test
	patch_gcc_default_pie_everywhere
	patch_gcc_unapplicable_ada
	patch_gcc_arc_multilib_multiarch
	patch_gcc_rtlibs_libatomic
	patch_gcc_cross_fixes_diff
	patch_gcc_wdotap
}

buildenv_gdbm() {
	if dpkg-architecture "-a$1" -ignu-any-any; then
		export ac_cv_func_mmap_fixed_mapped=yes
	fi
}

add_automatic glib2.0
patch_glib2_0() {
	dpkg-architecture "-a$HOST_ARCH" -ix32-any-any-any || return 0
	# https://github.com/mesonbuild/meson/issues/9845
	echo "working around wrong cc_can_run on x32"
	drop_privs sed -i -e '/set-cross-properties/a\		needs_exe_wrapper=true \\' debian/rules
}

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
}

add_automatic gmp

builddep_gnu_efi() {
	# binutils dependency needs cross translation
	apt_get_install debhelper
}

add_automatic gnupg2
add_automatic gpm

add_automatic grep
patch_grep() {
	dpkg-architecture "-a$HOST_ARCH" -imusl-linux-any || return 0
	echo "making grep use its internal regex library on musl #1008952"
	drop_privs patch -p1 <<'EOF'
--- a/debian/rules
+++ b/debian/rules
@@ -26,10 +26,12 @@
 DEB_CONFIGURE_SCRIPT_ENV += CPPFLAGS="$(CPPFLAGS)"
 ##########################################################################

+include /usr/share/dpkg/architecture.mk
+
 DEB_UPSTREAM_URL = http://ftp.gnu.org/gnu/grep/
 DEB_UPSTREAM_TARBALL_EXTENSION = tar.xz

-DEB_CONFIGURE_EXTRA_FLAGS += --without-included-regex
+DEB_CONFIGURE_EXTRA_FLAGS += --with$(if $(filter $(DEB_HOST_ARCH_LIBC),musl),,out)-included-regex
 DEB_CONFIGURE_SCRIPT_ENV += LIBS="$(LIBS)"

 # FIXME: CDBS should include a specific var for this
EOF
}

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

add_automatic gzip
patch_gzip() {
	test "$(dpkg-architecture "-a$HOST_ARCH" -qDEB_HOST_ARCH_BITS)" = 32 || return 0
	echo "fixing time_t ftcbfs #1009893"
	drop_privs sed -i -e '/CONFIGURE_ARGS.*--host/s/$/ --build=${DEB_BUILD_GNU_TYPE}/' debian/rules
}
buildenv_gzip() {
	if test "$LIBC_NAME" = musl; then
		# this avoids replacing fseeko with a variant that is broken
		echo gl_cv_func_fflush_stdin exported
		export gl_cv_func_fflush_stdin=yes
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
	if test "$HOST_ARCH" = arc; then
		echo "patch libgc for arc #994211"
		# https://github.com/ivmai/bdwgc/commit/968818a12c361a3a7fa6e8d8b851d04847335e58.patch
		drop_privs patch -p1 <<'EOF'
From 968818a12c361a3a7fa6e8d8b851d04847335e58 Mon Sep 17 00:00:00 2001
From: Vineet Gupta <vgupta@synopsys.com>
Date: Fri, 2 Apr 2021 10:13:15 -0700
Subject: [PATCH] Add support of Linux/arc

Issue #351 (bdwgc).

* include/private/gcconfig.h [__arc__ && LINUX] (ARC): Define
macro.
* include/private/gcconfig.h [ARC] (CPP_WORDSZ, MACH_TYPE, ALIGNMENT,
CACHE_LINE_SIZE): Likewise.
* include/private/gcconfig.h [ARC && LINUX] (OS_TYPE,
LINUX_STACKBOTTOM, COUNT_UNMAPPED_REGIONS, DYNAMIC_LOADING,
DATASTART): Likewise.
* include/private/gcconfig.h [ARC && LINUX] (__data_start): Declare
extern variable.
---
 include/private/gcconfig.h | 19 +++++++++++++++++++
 1 file changed, 19 insertions(+)

diff --git a/include/private/gcconfig.h b/include/private/gcconfig.h
index f500d20c9..8de3023bc 100644
--- a/include/private/gcconfig.h
+++ b/include/private/gcconfig.h
@@ -651,6 +651,10 @@ EXTERN_C_BEGIN
 #   define NONSTOP
 #   define mach_type_known
 # endif
+# if defined(__arc__) && defined(LINUX)
+#   define ARC
+#   define mach_type_known
+# endif
 # if defined(__hexagon__) && defined(LINUX)
 #    define HEXAGON
 #    define mach_type_known
@@ -2894,6 +2898,21 @@ EXTERN_C_BEGIN
 #   endif
 # endif /* X86_64 */
 
+# ifdef ARC
+#   define CPP_WORDSZ 32
+#   define MACH_TYPE "ARC"
+#   define ALIGNMENT 4
+#   define CACHE_LINE_SIZE 64
+#   ifdef LINUX
+#     define OS_TYPE "LINUX"
+#     define LINUX_STACKBOTTOM
+#     define COUNT_UNMAPPED_REGIONS
+#     define DYNAMIC_LOADING
+      extern int __data_start[] __attribute__((__weak__));
+#     define DATASTART ((ptr_t)__data_start)
+#   endif
+# endif /* ARC */
+
 # ifdef HEXAGON
 #   define CPP_WORDSZ 32
 #   define MACH_TYPE "HEXAGON"
EOF
	fi
}
buildenv_libgc() {
	if dpkg-architecture "-a$1" -imusl-linux-any; then
		echo "ignoring symbol differences for musl for now"
		export DPKG_GENSYMBOLS_CHECK_LEVEL=0
	fi
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
patch_libidn2() {
	dpkg-architecture "-a$HOST_ARCH" -imusl-linux-any || return 0
	echo "patching gettext version for musl support #999510"
	drop_privs patch -p1 <<'EOF'
--- a/configure.ac
+++ b/configure.ac
@@ -90,7 +90,8 @@
 ])

 AM_GNU_GETTEXT([external])
-AM_GNU_GETTEXT_VERSION([0.19.3])
+AM_GNU_GETTEXT_REQUIRE_VERSION([0.19.8])
+AM_GNU_GETTEXT_VERSION([0.19.6])

 AX_CODE_COVERAGE

EOF
	# must be newer than configure.ac
	drop_privs touch doc/idn2.1
}

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

patch_libxcrypt() {
	dpkg-architecture "-a$HOST_ARCH" -imusl-any-any || return 0
	echo "adding musl support #1004102"
	drop_privs patch -p1 <<'EOF'
--- a/debian/control
+++ b/debian/control
@@ -11,7 +11,7 @@

 Package: libcrypt1
 Section: libs
-Architecture: any
+Architecture: gnu-any-any
 Multi-Arch: same
 Pre-Depends: ${misc:Pre-Depends}
 Depends: ${shlibs:Depends}, ${misc:Depends}
@@ -29,26 +29,45 @@
  It provides the traditional Unix 'crypt' and 'crypt_r' interfaces,
  as well as a set of extended interfaces like 'crypt_gensalt'.

+Package: libcrypt2
+Section: libs
+Architecture: musl-any-any
+Multi-Arch: same
+Pre-Depends: ${misc:Pre-Depends}
+Depends: ${shlibs:Depends}, ${misc:Depends}
+Breaks: musl (<< 1.2.2-2~)
+Replaces: musl (<< 1.2.2-2~)
+XB-Important: yes
+Protected: yes
+Description: libcrypt shared library
+ libxcrypt is a modern library for one-way hashing of passwords.
+ It supports DES, MD5, NTHASH, SUNMD5, SHA-2-256, SHA-2-512, and
+ bcrypt-based password hashes
+ It provides the traditional Unix 'crypt' and 'crypt_r' interfaces,
+ as well as a set of extended interfaces like 'crypt_gensalt'.
+
 Package: libcrypt-dev
 Section: libdevel
 Architecture: any
 Multi-Arch: same
 Depends: ${shlibs:Depends}, ${misc:Depends}, ${LIBPKG} (= ${binary:Version})
-Provides: libcrypt1-dev
+Provides: ${LIBPKG}-dev
 Conflicts: libcrypt1-dev, libcrypt2-dev
 Breaks:
  libc6-dev (<< 2.29-4),
  libc6.1-dev (<< 2.29-4) [alpha ia64],
  libc0.1-dev (<< 2.29-4) [kfreebsd-amd64 kfreebsd-i386],
  libc0.3-dev (<< 2.29-4) [hurd-i386],
  manpages-dev (<< 5.01-1),
+ musl-dev (<< 1.2.2-2~) [musl-linux-any],
 Replaces:
  libcrypt1-dev, libcrypt2-dev,
  libc6-dev (<< 2.29-4),
  libc6.1-dev (<< 2.29-4) [alpha ia64],
  libc0.1-dev (<< 2.29-4) [kfreebsd-amd64 kfreebsd-i386],
  libc0.3-dev (<< 2.29-4) [hurd-i386],
  manpages-dev (<< 5.01-1),
+ musl-dev (<< 1.2.2-2~) [musl-linux-any],
 Description: libcrypt development files
  This package contains the files needed for developing applications that
  use libcrypt.
@@ -56,7 +71,7 @@
 Package: libcrypt1-udeb
 Package-Type: udeb
 Section: debian-installer
-Architecture: any
+Architecture: gnu-any-any
 Pre-Depends: ${misc:Pre-Depends}
 Depends: ${misc:Depends}
 Description: libcrypt shared library
--- a/debian/libcrypt2.symbols
+++ b/debian/libcrypt2.symbols
@@ -4,7 +4,6 @@
  XCRYPT_4.4@XCRYPT_4.4 1:4.4.0
  crypt@XCRYPT_2.0 1:4.1.0
  crypt_checksalt@XCRYPT_4.3 1:4.3.0
- crypt_gensalt_r@XCRYPT_2.0 1:4.3.4
  crypt_gensalt@XCRYPT_2.0 1:4.1.0
  crypt_gensalt_ra@XCRYPT_2.0 1:4.1.0
  crypt_gensalt_rn@XCRYPT_2.0 1:4.1.0
@@ -12,7 +11,3 @@
  crypt_r@XCRYPT_2.0 1:4.1.0
  crypt_ra@XCRYPT_2.0 1:4.1.0
  crypt_rn@XCRYPT_2.0 1:4.1.0
- xcrypt@XCRYPT_2.0 1:4.3.4
- xcrypt_gensalt@XCRYPT_2.0 1:4.3.4
- xcrypt_gensalt_r@XCRYPT_2.0 1:4.3.4
- xcrypt_r@XCRYPT_2.0 1:4.3.4
--- a/debian/rules
+++ b/debian/rules
@@ -30,7 +30,8 @@
 DS  := $(CURDIR)/debian/libxcrypt-source

 CONFFLAGS = --disable-werror --prefix=/usr \
-  --disable-xcrypt-compat-files --enable-obsolete-api=glibc
+  --disable-xcrypt-compat-files --enable-obsolete-api=glibc \
+  --includedir=/usr/include/$(DEB_HOST_MULTIARCH)
 CONFFLAGS_deb  = $(CONFFLAGS) \
   $(shell DEB_BUILD_MAINT_OPTIONS="hardening=+bindnow" \
     dpkg-buildflags --export=configure || true) \
EOF
}

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
	apt_get_install debhelper gawk patchutils bison flex lsb-release quilt libtool $GCC_AUTOCONF zlib1g-dev libmpc-dev libmpfr-dev libgmp-dev systemtap-sdt-dev sharutils "binutils$HOST_ARCH_SUFFIX" time
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
	apt_get_install debhelper gawk patchutils bison flex lsb-release quilt libtool $GCC_AUTOCONF zlib1g-dev libmpc-dev libmpfr-dev libgmp-dev dejagnu systemtap-sdt-dev sharutils "binutils$HOST_ARCH_SUFFIX" time
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
	if ! command -v "$compiler" >/dev/null; then echo "$compiler missing in stage3 gcc package"; exit 1; fi
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
	apt_get_install debhelper gawk patchutils bison flex lsb-release quilt libtool $GCC_AUTOCONF zlib1g-dev libmpc-dev libmpfr-dev libgmp-dev dejagnu systemtap-sdt-dev sharutils "binutils$HOST_ARCH_SUFFIX" "libc-dev:$HOST_ARCH" time
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

# libcrypt1-dev is defacto build-essential, because unstaged libc6-dev (and
# later build-essential) depends on it.
cross_build libxcrypt
apt_get_install "libcrypt-dev:$HOST_ARCH"
progress_mark libxcrypt
# is defacto build-essential

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
	# work around #995195
	mkdir /tmp/nodebugedit
	if test "$(dpkg-architecture "-a$HOST_ARCH" -qDEB_HOST_ARCH_ENDIAN)" != "$(dpkg-architecture -qDEB_HOST_ARCH_ENDIAN)"; then
		ln -s /bin/true /tmp/nodebugedit/debugedit
	fi
	PATH="/tmp/nodebugedit:$PATH" DEB_BUILD_OPTIONS="$DEB_BUILD_OPTIONS nocross nomult" drop_privs dpkg-buildpackage "-a$HOST_ARCH" -Pnocheck -B -uc -us
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

assert_built "$need_packages"

echo "checking installability of build-essential with dose"
apt_get_install botch
package_list=$(mktemp -t packages.XXXXXXXXXX)
grep-dctrl --exact --field Architecture '(' "$HOST_ARCH" --or all ')' /var/lib/apt/lists/*_Packages > "$package_list"
botch-distcheck-more-problems "--deb-native-arch=$HOST_ARCH" --successes --failures --explain --checkonly "build-essential:$HOST_ARCH" "--bg=deb://$package_list" "--fg=deb://$package_list" || :
rm -f "$package_list"
