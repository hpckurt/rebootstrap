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
DEFAULT_PROFILES="cross nocheck noudeb"
LIBC_NAME=glibc
DROP_PRIVS=buildd
GCC_NOLANG="ada asan brig d go itm java jit hppa64 lsan nvptx objc obj-c++ tsan ubsan"
ENABLE_DIFFOSCOPE=no

if df -t tmpfs /var/cache/apt/archives >/dev/null 2>&1; then
	APT_GET="$APT_GET -o APT::Keep-Downloaded-Packages=false"
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
	$APT_GET install adduser fakeroot
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
	$APT_GET install cross-gcc-dev
	echo "removing unused unstripped_exe patch"
	sed -i '/made-unstripped_exe-setting-overridable/d' /usr/share/cross-gcc/patches/gcc-*/series
	if test "$GCC_VER" = 9; then
		echo "fixing patch application for gcc-9 #928035"
		sed -i -e 's/\(`TARGET\))/\1/' /usr/share/cross-gcc/patches/gcc-9/*-now-depend-on-cpp-*
		echo "dropping libmpx from patch for gcc-9 #927230"
	patch /usr/share/cross-gcc/patches/gcc-9/*-multi-arch-specific-install-location-* <<'EOF'
--- a
+++ b
@@ -16,7 +16,7 @@
 index 0000000..7dd01d0
 --- /dev/null
 +++ b/debian/patches/cross-ma-install-location.diff
-@@ -0,0 +1,357 @@
+@@ -0,0 +1,337 @@
 +Index: b/src/libada/configure.ac
 +===================================================================
 +--- a/src/libada/configure.ac
@@ -340,26 +340,6 @@
 +     toolexeclibdir='$(toolexecdir)/$(gcc_version)$(MULTISUBDIR)'
 +     ;;
 +   no)
-+-    if test -n "$with_cross_host" &&
-+-       test x"$with_cross_host" != x"no"; then
-+-      # Install a library built with a cross compiler in tooldir, not libdir.
-+-      toolexecdir='$(exec_prefix)/$(target_alias)'
-+-      toolexeclibdir='$(toolexecdir)/lib'
-+-    else
-+-      toolexecdir='$(libdir)/gcc-lib/$(target_alias)'
-+-      toolexeclibdir='$(libdir)'
-+-    fi
-++    toolexecdir='$(libdir)/gcc-lib/$(target_alias)'
-++    toolexeclibdir='$(libdir)'
-+     multi_os_directory=`$CC -print-multi-os-directory`
-+     case $multi_os_directory in
-+       .) ;; # Avoid trailing /.
-+--- a/src/libmpx/configure.ac
-++++ b/src/libmpx/configure.ac
-+@@ -70,15 +70,8 @@
-+     toolexeclibdir='$(toolexecdir)/$(gcc_version)$(MULTISUBDIR)'
-+     ;;
-+   no)
 +-    if test -n "$with_cross_host" &&
 +-       test x"$with_cross_host" != x"no"; then
 +-      # Install a library built with a cross compiler in tooldir, not libdir.
EOF
	fi
fi

obtain_source_package() {
	local use_experimental
	use_experimental=
	case "$1" in
		gcc-[0-9]*)
			test -n "$(apt-cache showsrc "$1")" || use_experimental=yes
		;;
		libffi)
			# pull riscv64 support #892217
			test "$HOST_ARCH" = riscv64 && use_experimental=yes
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

# Work around libglib2.0-0 bug #814668. Running kfreebsd-i386 binaries on linux
# can result in clock jumps.
cat >/etc/dpkg/dpkg.cfg.d/bug-814668 <<EOF
path-exclude=/usr/lib/$(dpkg-architecture "-a$HOST_ARCH" -qDEB_HOST_MULTIARCH)/glib-2.0/glib-compile-schemas
path-exclude=/usr/lib/$(dpkg-architecture "-a$HOST_ARCH" -qDEB_HOST_MULTIARCH)/glib-2.0/gio-querymodules
EOF

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
	$APT_GET install devscripts
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
	profiles=`echo "$profiles" | sed 's/ /,/g;s/,,*/,/g;s/^,//;s/,$//'`
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
add_automatic adns

builddep_apt() {
	# g++ dependency needs toolchain translation
	assert_built "bzip2 curl db-defaults db5.3 gnutls28 lz4 xz-utils zlib libzstd"
	apt_get_install cmake debhelper dh-systemd docbook-xml docbook-xsl dpkg-dev gettext "libbz2-dev:$1" "libcurl4-gnutls-dev:$1" "libdb-dev:$1" "libgnutls28-dev:$1" "liblz4-dev:$1" "liblzma-dev:$1" pkg-config po4a xsltproc "zlib1g-dev:$1" "libzstd-dev:$1"
}

add_automatic attr
add_automatic autogen
add_automatic base-files
add_automatic base-passwd
add_automatic bash

patch_binutils() {
	if test "$HOST_ARCH" = "hurd-amd64"; then
		echo "patching binutils for hurd-amd64"
		drop_privs patch -p1 <<'EOF'
--- a/bfd/config.bfd
+++ b/bfd/config.bfd
@@ -671,7 +671,7 @@
     targ_selvecs="i386_elf32_vec i386_aout_nbsd_vec i386_coff_vec i386_pei_vec x86_64_pei_vec l1om_elf64_vec k1om_elf64_vec"
     want64=true
     ;;
-  x86_64-*-linux-*)
+  x86_64-*-linux-* | x86_64-*-gnu*)
     targ_defvec=x86_64_elf64_vec
     targ_selvecs="i386_elf32_vec x86_64_elf32_vec i386_aout_linux_vec i386_pei_vec x86_64_pei_vec l1om_elf64_vec k1om_elf64_vec"
     want64=true
--- a/ld/configure.tgt
+++ b/ld/configure.tgt
@@ -311,6 +311,7 @@
 i[3-7]86-*-mach*)	targ_emul=i386mach ;;
 i[3-7]86-*-gnu*)	targ_emul=elf_i386
 			targ_extra_emuls=elf_iamcu ;;
+x86_64-*-gnu*)		targ_emul=elf_x86_64 ;;
 i[3-7]86-*-msdos*)	targ_emul=i386msdos; targ_extra_emuls=i386aout ;;
 i[3-7]86-*-moss*)	targ_emul=i386moss; targ_extra_emuls=i386msdos ;;
 i[3-7]86-*-winnt*)	targ_emul=i386pe ;
EOF
	fi
	if test "$HOST_ARCH" = "kfreebsd-armhf"; then
		echo "patching binutils for kfreebsd-armhf"
		drop_privs patch -p1 <<'EOF'
--- a/bfd/config.bfd
+++ b/bfd/config.bfd
@@ -337,7 +337,7 @@
     targ_selvecs=arm_elf32_be_vec
     ;;
   arm-*-elf | arm*-*-freebsd* | arm*-*-linux-* | arm*-*-conix* | \
-  arm*-*-uclinux* | arm-*-kfreebsd*-gnu | \
+  arm*-*-uclinux* | arm-*-kfreebsd*-gnu* | \
   arm*-*-eabi* | arm-*-rtems*)
     targ_defvec=arm_elf32_le_vec
     targ_selvecs=arm_elf32_be_vec
--- a/gas/configure.tgt
+++ b/gas/configure.tgt
@@ -140,7 +140,8 @@
   arm-*-conix*)				fmt=elf ;;
   arm-*-freebsd[89].* | armeb-*-freebsd[89].*)
 					fmt=elf  em=freebsd ;;
-  arm-*-freebsd* | armeb-*-freebsd*)	fmt=elf  em=armfbsdeabi ;;
+  arm-*-freebsd* | armeb-*-freebsd* | arm-*-kfreebsd-gnueabi*)
+                                       fmt=elf  em=armfbsdeabi ;;
   arm*-*-freebsd*)			fmt=elf  em=armfbsdvfp ;;
   arm-*-linux*aout*)			fmt=aout em=linux ;;
   arm-*-linux-*eabi*)			fmt=elf  em=armlinuxeabi ;;
--- a/ld/configure.tgt
+++ b/ld/configure.tgt
@@ -83,7 +83,7 @@
 arm-*-coff)		targ_emul=armcoff ;;
 arm*b-*-freebsd*)	targ_emul=armelfb_fbsd
 			targ_extra_emuls="armelf_fbsd armelf" ;;
-arm*-*-freebsd* | arm-*-kfreebsd*-gnu)
+arm*-*-freebsd* | arm-*-kfreebsd*-gnu*)
 	       		targ_emul=armelf_fbsd
 			targ_extra_emuls="armelfb_fbsd armelf" ;;
 armeb-*-netbsdelf*)	targ_emul=armelfb_nbsd;
EOF
	fi
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
}

add_automatic blt
buildenv_blt() {
	# blt now knows which CC to use, but its configure misdetects tons of
	# stuff when you tell it explicitly.
	unset CC
}

add_automatic bsdmainutils

builddep_build_essential() {
	# g++ dependency needs cross translation
	$APT_GET install debhelper python3
}

add_automatic bzip2
add_automatic c-ares
add_automatic coreutils
add_automatic curl

builddep_cyrus_sasl2() {
	assert_built "db-defaults db5.3 openssl pam"
	# many packages droppable in stage1
	$APT_GET install debhelper quilt automake autotools-dev "libdb-dev:$1" "libpam0g-dev:$1" "libssl-dev:$1" chrpath groff-base po-debconf docbook-to-man dh-autoreconf
}

add_automatic dash
add_automatic datefudge
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
patch_e2fsprogs() {
	echo "fixing DEB_BUILD_OPTIONS=nocheck #933247"
	patch -p1 <<'EOF'
--- a/debian/rules
+++ b/debian/rules
@@ -170,7 +170,9 @@
 	dh_gencontrol --remaining-packages

 override_dh_auto_test:
+ifeq (,$(filter nocheck,$(DEB_BUILD_OPTIONS)))
 	$(MAKE) -C ${stdbuilddir} V=1 check
+endif

 test_printenv:
 	printenv | sort
EOF
}

add_automatic elfutils
add_automatic expat
add_automatic file
add_automatic findutils
add_automatic flex
add_automatic fontconfig
add_automatic freebsd-glue
add_automatic freetype
add_automatic fribidi
add_automatic fuse

patch_gcc_multilib_deps() {
	test "$ENABLE_MULTIARCH_GCC" != yes || return 0
	echo "fixing multilib libc dependencies #862756"
	drop_privs patch -p1 <<'EOF'
--- a/debian/rules.defs
+++ b/debian/rules.defs
@@ -1960,7 +1960,7 @@
 	if [ -f debian/$(1).substvars ]; then \
 	  sed -i \
 	    -e 's/:$(DEB_TARGET_ARCH)/$(cross_lib_arch)/g' \
-	    -e 's/\(libc[.0-9]*-[^:]*\):\([a-z0-9-]*\)/\1-\2-cross/g' \
+	    -e 's/\(libc[.0-9]*-[^: ]*\)\(:$(DEB_TARGET_ARCH)\)\?/\1$(cross_lib_arch)/g' \
 	    $(if $(filter armel,$(DEB_TARGET_ARCH)),-e 's/:armhf/-armhf-cross/g') \
 	    $(if $(filter armhf,$(DEB_TARGET_ARCH)),-e 's/:armel/-armel-cross/g') \
 	    debian/$(1).substvars; \
EOF
}
patch_gcc_arm64ilp32() {
	test "$HOST_ARCH" = arm64ilp32 || return 0
	echo "add support for arm64ilp32 #874583"
	drop_privs tee debian/patches/arm64-ilp32-default.diff >/dev/null <<'EOF'
--- a/src/gcc/config.gcc
+++ b/src/gcc/config.gcc
@@ -515,12 +515,15 @@
 	tm_p_file="${tm_p_file} arm/aarch-common-protos.h"
 	case ${with_abi} in
 	"")
-		if test "x$with_multilib_list" = xilp32; then
+		case ${target} in
+		aarch64*-*-*_ilp32)
 			tm_file="aarch64/biarchilp32.h ${tm_file}"
-		else
+			;;
+		*)
 			tm_file="aarch64/biarchlp64.h ${tm_file}"
-		fi
-		;;
+			;;
+		esac
+		;;
 	ilp32)
 		tm_file="aarch64/biarchilp32.h ${tm_file}"
 		;;
@@ -965,9 +965,16 @@
 	esac
 	aarch64_multilibs="${with_multilib_list}"
 	if test "$aarch64_multilibs" = "default"; then
-		# TODO: turn on ILP32 multilib build after its support is mature.
-		# aarch64_multilibs="lp64,ilp32"
-		aarch64_multilibs="lp64"
+		case $target in
+		aarch64*_ilp32*)
+			aarch64_multilibs="ilp32"
+			;;
+		aarch64*)
+			# TODO: turn on ILP32 multilib build after its support is mature.
+			# aarch64_multilibs="lp64,ilp32"
+			aarch64_multilibs="lp64"
+			;;
+		esac
 	fi
 	aarch64_multilibs=`echo $aarch64_multilibs | sed -e 's/,/ /g'`
 	for aarch64_multilib in ${aarch64_multilibs}; do
EOF
	if ! grep -q arm64-ilp32-default debian/rules.patch; then
		echo "debian_patches += arm64-ilp32-default" | drop_privs tee -a debian/rules.patch >/dev/null
	fi
	drop_privs patch -p1 <<'EOF'
--- a/debian/patches/gcc-multilib-multiarch.diff
+++ b/debian/patches/gcc-multilib-multiarch.diff
@@ -124,3 +124,22 @@
  else
  MULTIARCH_DIRNAME := powerpc-linux-gnu
  endif
+Index: b/src/gcc/config/aarch64/t-aarch64-linux
+===================================================================
+--- a/src/gcc/config/aarch64/t-aarch64-linux	2018-09-02 02:55:29.497080395 +0100
++++ b/src/gcc/config/aarch64/t-aarch64-linux	2018-09-02 02:58:07.985592927 +0100
+@@ -22,7 +22,14 @@
+ LIB1ASMFUNCS = _aarch64_sync_cache_range
+
+ AARCH_BE = $(if $(findstring TARGET_BIG_ENDIAN_DEFAULT=1, $(tm_defines)),_be)
++ifneq (,$(findstring _ilp32,$(target)))
++MULTILIB_OSDIRNAMES = mabi.lp64=../lib64$(call if_multiarch,:aarch64$(AARCH_BE)-linux-gnu)
++MULTIARCH_DIRNAME = $(call if_multiarch,aarch64$(AARCH_BE)-linux-gnu_ilp32)
++
++MULTILIB_OSDIRNAMES += mabi.ilp32=../lib$(call if_multiarch,:aarch64$(AARCH_BE)-linux-gnu_ilp32)
++else
+ MULTILIB_OSDIRNAMES = mabi.lp64=../lib$(call if_multiarch,:aarch64$(AARCH_BE)-linux-gnu)
+ MULTIARCH_DIRNAME = $(call if_multiarch,aarch64$(AARCH_BE)-linux-gnu)
+
+ MULTILIB_OSDIRNAMES += mabi.ilp32=../libilp32$(call if_multiarch,:aarch64$(AARCH_BE)-linux-gnu_ilp32)
++endif
EOF
}
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
patch_gcc_wdotap() {
	if test "$ENABLE_MULTIARCH_GCC" = yes; then
		echo "applying patches for with_deps_on_target_arch_pkgs"
		drop_privs QUILT_PATCHES="/usr/share/cross-gcc/patches/gcc-$GCC_VER" quilt push -a
		drop_privs rm -Rf .pc
	fi
}
patch_gcc_8() {
	echo "fix LIMITS_H_TEST again https://gcc.gnu.org/bugzilla/show_bug.cgi?id=80677"
	drop_privs sed -i -e 's,^\(+LIMITS_H_TEST = \).*,\1:,' debian/patches/gcc-multiarch.diff
	patch_gcc_arm64ilp32
	patch_gcc_default_pie_everywhere
	patch_gcc_multilib_deps
	echo "build common libraries again, not a bug"
	drop_privs sed -i -e 's/^\s*#\?\(with_common_libs\s*:\?=\).*/\1yes/' debian/rules.defs
	patch_gcc_wdotap
}
patch_gcc_9() {
	echo "fix LIMITS_H_TEST again https://gcc.gnu.org/bugzilla/show_bug.cgi?id=80677"
	drop_privs sed -i -e 's,^\(+LIMITS_H_TEST = \).*,\1:,' debian/patches/gcc-multiarch.diff
	patch_gcc_wdotap
}

buildenv_gdbm() {
	if dpkg-architecture "-a$1" -ignu-any-any; then
		export ac_cv_func_mmap_fixed_mapped=yes
	fi
}

buildenv_glib2_0() {
	export glib_cv_stack_grows=no
	export glib_cv_uscore=no
	export ac_cv_func_posix_getgrgid_r=yes
	export ac_cv_func_posix_getpwuid_r=yes
}
patch_glib2_0() {
	echo "allow building with any gcc"
	sed -i -e '/\(gcc\|cpp\)-8/d' debian/rules
	sed -i -e '/gcc-8/d' -e 's/^\(Build-Depends:\) cpp-8,/\1/' debian/control
	echo "fix glib2.0's debcrossgen fork #933560"
	drop_privs patch -p1 <<'EOF'
--- a/debian/debcrossgen
+++ b/debian/debcrossgen
@@ -47,6 +50,36 @@
             return f
     raise ValueError("%s not found on $PATH" % program)
 
+def write_args_line(ofile, name, args):
+    if len(args) == 0:
+        return
+    ostr = name + ' = ['
+    ostr += ', '.join("'" + i + "'" for i in args)
+    ostr += ']\n'
+    ofile.write(ostr)
+
+def write_args_from_envvars(ofile):
+    import shlex
+    cppflags = shlex.split(os.environ.get('CPPFLAGS', ''))
+    cflags = shlex.split(os.environ.get('CFLAGS', ''))
+    cxxflags = shlex.split(os.environ.get('CXXFLAGS', ''))
+    ldflags = shlex.split(os.environ.get('LDFLAGS', ''))
+
+    c_args = cppflags + cflags
+    cpp_args = cppflags + cxxflags
+    c_link_args = cflags + ldflags
+    cpp_link_args = cxxflags + ldflags
+
+    write_args_line(ofile, 'c_args', c_args)
+    write_args_line(ofile, 'cpp_args', cpp_args)
+    write_args_line(ofile, 'c_link_args', c_link_args)
+    write_args_line(ofile, 'cpp_link_args', cpp_link_args)
+
+cpu_family_map = dict(mips64el="mips64",
+                      i686='x86')
+cpu_map = dict(armhf="arm7hlf",
+               mips64el="mips64",)
+
 def run(options):
     if options.arch is None:
         cmd = ['dpkg-architecture']
@@ -62,8 +95,10 @@
         data[k] = v
     host_arch = data['DEB_HOST_GNU_TYPE']
     host_os = data['DEB_HOST_ARCH_OS']
-    host_cpu_family = data['DEB_HOST_GNU_CPU']
-    host_cpu = data['DEB_HOST_ARCH'] # Not really correct, should be arm7hlf etc but it is not exposed.
+    host_cpu_family = cpu_family_map.get(data['DEB_HOST_GNU_CPU'],
+                                         data['DEB_HOST_GNU_CPU'])
+    host_cpu = cpu_map.get(data['DEB_HOST_ARCH'],
+                           data['DEB_HOST_ARCH'])
     host_endian = data['DEB_HOST_ARCH_ENDIAN']
     with open(options.outfile, "w") as ofile:
         ofile.write('[binaries]\n')
@@ -80,6 +115,7 @@
         except ValueError:
             pass # pkg-config is optional
         ofile.write('\n[properties]\n')
+        write_args_from_envvars(ofile)
         for prop in options.set:
             assert '=' in prop
             key, value = prop.split('=', 1)
EOF
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
			test "$2" = stage1 || apt_get_install "libihash-dev:$1"
		;;
		kfreebsd)
			apt_get_install "kfreebsd-kernel-headers:$1"
		;;
		*)
			echo "rebootstrap-error: unsupported kernel"
			exit 1
		;;
	esac
}
patch_glibc() {
	echo "patching eglibc to avoid dependency on libc6 from libc6-dev in stage1"
	drop_privs sed -i '/^Depends:/s/\(\(libc[0-9.]\+-[^d]\|@libc@\)[^,]*\)\(,\|$\)/\1 <!stage1>\3/g' debian/control.in/*
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
@@ -2,6 +2,20 @@
 # PASS_VAR, we need to call all variables as $(call xx,VAR)
 # This little bit of magic makes it possible:
 xx=$(if $($(curpass)_$(1)),$($(curpass)_$(1)),$($(1)))
+define generic_multilib_extra_pkg_install
+set -e; \
+mkdir -p debian/$(1)/usr/include; \
+for i in `ls debian/tmp-libc/usr/include/$(DEB_HOST_MULTIARCH)`; do \
+	if test -d debian/tmp-libc/usr/include/$(DEB_HOST_MULTIARCH)/$$i && ! test $$i = bits -o $$i = gnu; then \
+		mkdir -p debian/$(1)/usr/include/$$i; \
+		for j in `ls debian/tmp-libc/usr/include/$(DEB_HOST_MULTIARCH)/$$i`; do \
+			ln -sf ../$(DEB_HOST_MULTIARCH)/$$i/$$j debian/$(1)/usr/include/$$i/$$j; \
+		done; \
+	else \
+		ln -sf $(DEB_HOST_MULTIARCH)/$$i debian/$(1)/usr/include/$$i; \
+	fi; \
+done
+endef
 
 ifneq ($(filter stage1,$(DEB_BUILD_PROFILES)),)
     libc_extra_config_options = $(extra_config_options) --disable-sanity-checks \
@@ -218,13 +218,9 @@
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
 	fi
 
 	# For our biarch libc, add an ld.so.conf.d configuration; this
--- a/debian/sysdeps/ppc64.mk
+++ b/debian/sysdeps/ppc64.mk
@@ -15,20 +15,12 @@

 define libc6-dev-powerpc_extra_pkg_install

-mkdir -p debian/libc6-dev-powerpc/usr/include
-ln -s powerpc64-linux-gnu/bits debian/libc6-dev-powerpc/usr/include/
-ln -s powerpc64-linux-gnu/gnu debian/libc6-dev-powerpc/usr/include/
-ln -s powerpc64-linux-gnu/fpu_control.h debian/libc6-dev-powerpc/usr/include/
+$(call generic_multilib_extra_pkg_install,libc6-dev-powerpc)

 mkdir -p debian/libc6-dev-powerpc/usr/include/powerpc64-linux-gnu/gnu
 cp -a debian/tmp-powerpc/usr/include/gnu/lib-names-32.h \
 	debian/tmp-powerpc/usr/include/gnu/stubs-32.h \
 	debian/libc6-dev-powerpc/usr/include/powerpc64-linux-gnu/gnu
-
-mkdir -p debian/libc6-dev-powerpc/usr/include/sys
-for i in `ls debian/tmp-libc/usr/include/powerpc64-linux-gnu/sys` ; do \
-	ln -s ../powerpc64-linux-gnu/sys/$$i debian/libc6-dev-powerpc/usr/include/sys/$$i ; \
-done

 endef

--- a/debian/sysdeps/mips.mk
+++ b/debian/sysdeps/mips.mk
@@ -31,20 +31,12 @@

 define libc6-dev-mips64_extra_pkg_install
 
-mkdir -p debian/libc6-dev-mips64/usr/include
-ln -sf mips-linux-gnu/bits debian/libc6-dev-mips64/usr/include/
-ln -sf mips-linux-gnu/gnu debian/libc6-dev-mips64/usr/include/
-ln -sf mips-linux-gnu/fpu_control.h debian/libc6-dev-mips64/usr/include/
+$(call generic_multilib_extra_pkg_install,libc6-dev-mips64)
 
 mkdir -p debian/libc6-dev-mips64/usr/include/mips-linux-gnu/gnu
 cp -a debian/tmp-mips64/usr/include/gnu/lib-names-n64_hard.h \
 	debian/tmp-mips64/usr/include/gnu/stubs-n64_hard.h \
 	debian/libc6-dev-mips64/usr/include/mips-linux-gnu/gnu
-
-mkdir -p debian/libc6-dev-mips64/usr/include/sys
-for i in `ls debian/tmp-libc/usr/include/mips-linux-gnu/sys` ; do \
-	ln -sf ../mips-linux-gnu/sys/$$i debian/libc6-dev-mips64/usr/include/sys/$$i ; \
-done
 
 endef
 
--- a/debian/sysdeps/mipsel.mk
+++ b/debian/sysdeps/mipsel.mk
@@ -31,20 +31,12 @@

 define libc6-dev-mips64_extra_pkg_install

-mkdir -p debian/libc6-dev-mips64/usr/include
-ln -sf mipsel-linux-gnu/bits debian/libc6-dev-mips64/usr/include/
-ln -sf mipsel-linux-gnu/gnu debian/libc6-dev-mips64/usr/include/
-ln -sf mipsel-linux-gnu/fpu_control.h debian/libc6-dev-mips64/usr/include/
+$(call generic_multilib_extra_pkg_install,libc6-dev-mips64)

 mkdir -p debian/libc6-dev-mips64/usr/include/mipsel-linux-gnu/gnu
 cp -a debian/tmp-mips64/usr/include/gnu/lib-names-n64_hard.h \
 	debian/tmp-mips64/usr/include/gnu/stubs-n64_hard.h \
 	debian/libc6-dev-mips64/usr/include/mipsel-linux-gnu/gnu
-
-mkdir -p debian/libc6-dev-mips64/usr/include/sys
-for i in `ls debian/tmp-libc/usr/include/mipsel-linux-gnu/sys` ; do \
-	ln -sf ../mipsel-linux-gnu/sys/$$i debian/libc6-dev-mips64/usr/include/sys/$$i ; \
-done

 endef

--- a/debian/sysdeps/powerpc.mk
+++ b/debian/sysdeps/powerpc.mk
@@ -15,20 +15,12 @@

 define libc6-dev-ppc64_extra_pkg_install

-mkdir -p debian/libc6-dev-ppc64/usr/include
-ln -s powerpc-linux-gnu/bits debian/libc6-dev-ppc64/usr/include/
-ln -s powerpc-linux-gnu/gnu debian/libc6-dev-ppc64/usr/include/
-ln -s powerpc-linux-gnu/fpu_control.h debian/libc6-dev-ppc64/usr/include/
+$(call generic_multilib_extra_pkg_install,libc6-dev-ppc64)

 mkdir -p debian/libc6-dev-ppc64/usr/include/powerpc-linux-gnu/gnu
 cp -a debian/tmp-ppc64/usr/include/gnu/lib-names-64-v1.h \
 	debian/tmp-ppc64/usr/include/gnu/stubs-64-v1.h \
 	debian/libc6-dev-ppc64/usr/include/powerpc-linux-gnu/gnu
-
-mkdir -p debian/libc6-dev-ppc64/usr/include/sys
-for i in `ls debian/tmp-libc/usr/include/powerpc-linux-gnu/sys` ; do \
-	ln -s ../powerpc-linux-gnu/sys/$$i debian/libc6-dev-ppc64/usr/include/sys/$$i ; \
-done

 endef

--- a/debian/sysdeps/s390x.mk
+++ b/debian/sysdeps/s390x.mk
@@ -14,20 +14,12 @@

 define libc6-dev-s390_extra_pkg_install

-mkdir -p debian/libc6-dev-s390/usr/include
-ln -s s390x-linux-gnu/bits debian/libc6-dev-s390/usr/include/
-ln -s s390x-linux-gnu/gnu debian/libc6-dev-s390/usr/include/
-ln -s s390x-linux-gnu/fpu_control.h debian/libc6-dev-s390/usr/include/
+$(call generic_multilib_extra_pkg_install,libc6-dev-s390)

 mkdir -p debian/libc6-dev-s390/usr/include/s390x-linux-gnu/gnu
 cp -a debian/tmp-s390/usr/include/gnu/lib-names-32.h \
 	debian/tmp-s390/usr/include/gnu/stubs-32.h \
 	debian/libc6-dev-s390/usr/include/s390x-linux-gnu/gnu
-
-mkdir -p debian/libc6-dev-s390/usr/include/sys
-for i in `ls debian/tmp-libc/usr/include/s390x-linux-gnu/sys` ; do \
-	ln -s ../s390x-linux-gnu/sys/$$i debian/libc6-dev-s390/usr/include/sys/$$i ; \
-done

 endef

--- a/debian/sysdeps/sparc.mk
+++ b/debian/sysdeps/sparc.mk
@@ -15,19 +15,11 @@

 define libc6-dev-sparc64_extra_pkg_install

-mkdir -p debian/libc6-dev-sparc64/usr/include
-ln -s sparc-linux-gnu/bits debian/libc6-dev-sparc64/usr/include/
-ln -s sparc-linux-gnu/gnu debian/libc6-dev-sparc64/usr/include/
-ln -s sparc-linux-gnu/fpu_control.h debian/libc6-dev-sparc64/usr/include/
+$(call generic_multilib_extra_pkg_install,libc6-dev-sparc64)

 mkdir -p debian/libc6-dev-sparc64/usr/include/sparc-linux-gnu/gnu
 cp -a debian/tmp-sparc64/usr/include/gnu/lib-names-64.h \
 	debian/tmp-sparc64/usr/include/gnu/stubs-64.h \
 	debian/libc6-dev-sparc64/usr/include/sparc-linux-gnu/gnu
-
-mkdir -p debian/libc6-dev-sparc64/usr/include/sys
-for i in `ls debian/tmp-libc/usr/include/sparc-linux-gnu/sys` ; do \
-	ln -s ../sparc-linux-gnu/sys/$$i debian/libc6-dev-sparc64/usr/include/sys/$$i ; \
-done

 endef
EOF
	echo "patching glibc to work with regular kfreebsd-kernel-headers"
	drop_privs patch -p1 <<'EOF'
--- a/debian/sysdeps/kfreebsd.mk
+++ b/debian/sysdeps/kfreebsd.mk
@@ -13,7 +13,7 @@
 libc_extra_config_options = $(extra_config_options)

 ifndef KFREEBSD_SOURCE
-  ifeq ($(DEB_HOST_GNU_TYPE),$(DEB_BUILD_GNU_TYPE))
+  ifeq ($(shell dpkg-query --status kfreebsd-kernel-headers-$(DEB_HOST_ARCH)-cross 2>/dev/null),)
     KFREEBSD_HEADERS := /usr/include
   else
     KFREEBSD_HEADERS := /usr/$(DEB_HOST_GNU_TYPE)/include
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
	echo "don't force a gcc version"
	drop_privs sed -i -e '/^DEB_GCC_VERSION =/d' debian/sysdeps/armel.mk
}

add_automatic gmp
patch_gmp() {
	if test "$LIBC_NAME" = musl; then
		echo "patching gmp symbols for musl arch #788411"
		sed -i -r "s/([= ])(\!)?\<(${HOST_ARCH#musl-linux-})\>/\1\2\3 \2musl-linux-\3/" debian/libgmp10.symbols
		# musl does not implement GNU obstack
		sed -i -r 's/^ (.*_obstack_)/ (arch=!musl-linux-any !musleabihf-linux-any)\1/' debian/libgmp10.symbols
	fi
}

builddep_gnu_efi() {
	# binutils dependency needs cross translation
	$APT_GET install debhelper
}

add_automatic gnupg2
add_automatic gnutls28

add_automatic gpm
patch_gpm() {
	if dpkg-architecture "-a$HOST_ARCH" -imusl-linux-any; then
		echo "patching gpm to support musl #813751"
		drop_privs patch -p1 <<'EOF'
--- a/src/lib/liblow.c
+++ a/src/lib/liblow.c
@@ -173,7 +173,7 @@
   /* Reincarnation. Prepare for another death early. */
   sigemptyset(&sa.sa_mask);
   sa.sa_handler = gpm_suspend_hook;
-  sa.sa_flags = SA_NOMASK;
+  sa.sa_flags = SA_NODEFER;
   sigaction (SIGTSTP, &sa, 0);
 
   /* Pop the gpm stack by closing the useless connection */
@@ -350,7 +350,7 @@
 
          /* if signal was originally ignored, job control is not supported */
          if (gpm_saved_suspend_hook.sa_handler != SIG_IGN) {
-            sa.sa_flags = SA_NOMASK;
+            sa.sa_flags = SA_NODEFER;
             sa.sa_handler = gpm_suspend_hook;
             sigaction(SIGTSTP, &sa, 0);
          }
--- a/src/prog/display-buttons.c
+++ b/src/prog/display-buttons.c
@@ -36,6 +36,7 @@
 #include <stdio.h>            /* printf()             */
 #include <time.h>             /* time()               */
 #include <errno.h>            /* errno                */
+#include <sys/select.h>       /* fd_set, FD_ZERO      */
 #include <gpm.h>              /* gpm information      */
 
 /* display resulting data */
--- a/src/prog/display-coords.c
+++ b/src/prog/display-coords.c
@@ -37,6 +37,7 @@
 #include <stdio.h>            /* printf()             */
 #include <time.h>             /* time()               */
 #include <errno.h>            /* errno                */
+#include <sys/select.h>       /* fd_set, FD_ZERO      */
 #include <gpm.h>              /* gpm information      */
 
 /* display resulting data */
--- a/src/prog/gpm-root.y
+++ b/src/prog/gpm-root.y
@@ -1197,6 +1197,9 @@
    /* reap your zombies */
    childaction.sa_handler=reap_children;
    sigemptyset(&childaction.sa_mask);
+#ifndef SA_INTERRUPT
+#define SA_INTERRUPT 0
+#endif
    childaction.sa_flags=SA_INTERRUPT; /* need to break the select() call */
    sigaction(SIGCHLD,&childaction,NULL);
 
--- a/contrib/control/gpm_has_mouse_control.c
+++ a/contrib/control/gpm_has_mouse_control.c
@@ -1,4 +1,4 @@
-#include <sys/fcntl.h>
+#include <fcntl.h>
 #include <sys/kd.h>
 #include <stdio.h>
 #include <stdlib.h>
EOF
	fi
}

add_automatic grep
add_automatic groff
add_automatic guile-2.0
builddep_guile_2_0() {
	apt_get_build_dep "-a$HOST_ARCH" --arch-only -P cross ./
	if test "$HOST_ARCH" = sh3; then
		echo "adding sh3 support to guile-2.0 http://git.savannah.gnu.org/cgit/guile.git/commit/?id=92222727f81b2a03cde124b88d7e6224ecb29199"
		sed -i -e 's/"sh4"/"sh3" &/' /usr/share/guile/2.0/system/base/target.scm
	fi
}
patch_guile_2_0() {
	if test "$HOST_ARCH" = sh3; then
		echo "adding sh3 support to guile-2.0 http://git.savannah.gnu.org/cgit/guile.git/commit/?id=92222727f81b2a03cde124b88d7e6224ecb29199"
		sed -i -e 's/"sh4"/"sh3" &/' module/system/base/target.scm
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

patch_hurd() {
	echo "working around #818618"
	sed -i -e '/^#.*818618/d;s/^#//' debian/control
}

add_automatic icu
add_automatic isl
add_automatic isl-0.18
add_automatic jansson

add_automatic jemalloc
buildenv_jemalloc() {
	case "$(dpkg-architecture "-a$HOST_ARCH" -qDEB_HOST_ARCH_CPU)" in
		amd64|arm|arm64|hppa|i386|m68k|mips|s390x|sh3|sh4)
			echo "setting je_cv_static_page_shift=12"
			export je_cv_static_page_shift=12
		;;
		alpha|sparc|sparc64)
			echo "setting je_cv_static_page_shift=13"
			export je_cv_static_page_shift=13
		;;
		mips64el|mipsel|nios2)
			echo "setting je_cv_static_page_shift=14"
			export je_cv_static_page_shift=14
		;;
		powerpc|ppc64|ppc64el)
			echo "setting je_cv_static_page_shift=16"
			export je_cv_static_page_shift=16
		;;
	esac
}

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
	if test "$HOST_ARCH" = nios2; then
		echo "cherry-picking upstream commit https://github.com/ivmai/bdwgc/commit/2571df0e30b4976d7a12dbc6fbec4f1c4027924d"
		drop_privs patch -p1 <<'EOF'
--- a/include/private/gcconfig.h
+++ b/include/private/gcconfig.h
@@ -188,6 +188,10 @@
 #    endif
 #    define mach_type_known
 # endif
+# if defined(__NIOS2__) || defined(__NIOS2) || defined(__nios2__)
+#   define NIOS2 /* Altera NIOS2 */
+#   define mach_type_known
+# endif
 # if defined(__NetBSD__) && defined(__vax__)
 #    define VAX
 #    define mach_type_known
@@ -1729,6 +1733,24 @@
 #   endif
 # endif
 
+# ifdef NIOS2
+#  define CPP_WORDSZ 32
+#  define MACH_TYPE "NIOS2"
+#  ifdef LINUX
+#    define OS_TYPE "LINUX"
+#    define DYNAMIC_LOADING
+     extern int _end[];
+     extern int __data_start[];
+#    define DATASTART ((ptr_t)(__data_start))
+#    define DATAEND ((ptr_t)(_end))
+#    define ALIGNMENT 4
+#    ifndef HBLKSIZE
+#      define HBLKSIZE 4096
+#    endif
+#    define LINUX_STACKBOTTOM
+#  endif /* Linux */
+# endif
+
 # ifdef SH4
 #   define MACH_TYPE "SH4"
 #   define OS_TYPE "MSWINCE"
@@ -2800,7 +2822,8 @@

 #if ((defined(UNIX_LIKE) && (defined(DARWIN) || defined(HURD) \
                              || defined(OPENBSD) || defined(ARM32) \
-                             || defined(MIPS) || defined(AVR32))) \
+                             || defined(MIPS) || defined(AVR32) \
+                             || defined(NIOS2))) \
      || (defined(LINUX) && (defined(SPARC) || defined(M68K))) \
      || ((defined(RTEMS) || defined(PLATFORM_ANDROID)) && defined(I386))) \
     && !defined(NO_GETCONTEXT)
EOF
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
add_automatic libonig
add_automatic libpipeline
add_automatic libpng1.6

patch_libprelude() {
	echo "removing the unsatisfiable g++ build dependency"
	drop_privs sed -i -e '/^\s\+g++/d' debian/control
}
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
add_automatic libssh2
add_automatic libsystemd-dummy
add_automatic libtasn1-6
add_automatic libtextwrap

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
		arm|ia64|nios2)
			kernel_arch=$HOST_ARCH
		;;
		arm64ilp32) kernel_arch=arm64; ;;
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

builddep_ncurses() {
	if test "$(dpkg-architecture "-a$HOST_ARCH" -qDEB_HOST_ARCH_OS)" = linux; then
		assert_built gpm
		$APT_GET install "libgpm-dev:$1"
	fi
	# g++-multilib dependency unsatisfiable
	apt_get_install debhelper pkg-config autoconf-dickey
	case "$ENABLE_MULTILIB:$HOST_ARCH" in
		yes:amd64|yes:i386|yes:powerpc|yes:ppc64|yes:s390|yes:sparc)
			test "$1" = "$HOST_ARCH"
			$APT_GET install "g++-$GCC_VER-multilib$HOST_ARCH_SUFFIX"
			# the unversioned gcc-multilib$HOST_ARCH_SUFFIX should contain the following link
			ln -sf "`dpkg-architecture -a$HOST_ARCH -qDEB_HOST_MULTIARCH`/asm" /usr/include/asm
		;;
	esac
}

add_automatic nettle
add_automatic nghttp2
add_automatic npth

add_automatic nspr
patch_nspr() {
	echo "patching nspr for nios2 https://bugzilla.mozilla.org/show_bug.cgi?id=1244421"
	drop_privs patch -p1 <<'EOF'
--- a/nspr/pr/include/md/_linux.cfg
+++ b/nspr/pr/include/md/_linux.cfg
@@ -972,6 +972,51 @@
 #define PR_BYTES_PER_WORD_LOG2   2
 #define PR_BYTES_PER_DWORD_LOG2  3
 
+#elif defined(__nios2__)
+
+#define IS_LITTLE_ENDIAN    1
+#undef  IS_BIG_ENDIAN
+
+#define PR_BYTES_PER_BYTE   1
+#define PR_BYTES_PER_SHORT  2
+#define PR_BYTES_PER_INT    4
+#define PR_BYTES_PER_INT64  8
+#define PR_BYTES_PER_LONG   4
+#define PR_BYTES_PER_FLOAT  4
+#define PR_BYTES_PER_DOUBLE 8
+#define PR_BYTES_PER_WORD   4
+#define PR_BYTES_PER_DWORD  8
+
+#define PR_BITS_PER_BYTE    8
+#define PR_BITS_PER_SHORT   16
+#define PR_BITS_PER_INT     32
+#define PR_BITS_PER_INT64   64
+#define PR_BITS_PER_LONG    32
+#define PR_BITS_PER_FLOAT   32
+#define PR_BITS_PER_DOUBLE  64
+#define PR_BITS_PER_WORD    32
+
+#define PR_BITS_PER_BYTE_LOG2   3
+#define PR_BITS_PER_SHORT_LOG2  4
+#define PR_BITS_PER_INT_LOG2    5
+#define PR_BITS_PER_INT64_LOG2  6
+#define PR_BITS_PER_LONG_LOG2   5
+#define PR_BITS_PER_FLOAT_LOG2  5
+#define PR_BITS_PER_DOUBLE_LOG2 6
+#define PR_BITS_PER_WORD_LOG2   5
+
+#define PR_ALIGN_OF_SHORT   2
+#define PR_ALIGN_OF_INT     4
+#define PR_ALIGN_OF_LONG    4
+#define PR_ALIGN_OF_INT64   4
+#define PR_ALIGN_OF_FLOAT   4
+#define PR_ALIGN_OF_DOUBLE  4
+#define PR_ALIGN_OF_POINTER 4
+#define PR_ALIGN_OF_WORD    4
+
+#define PR_BYTES_PER_WORD_LOG2   2
+#define PR_BYTES_PER_DWORD_LOG2  3
+
 #elif defined(__or1k__)
 
 #undef  IS_LITTLE_ENDIAN
--- a/nspr/pr/include/md/_linux.h
+++ b/nspr/pr/include/md/_linux.h
@@ -55,6 +55,8 @@
 #define _PR_SI_ARCHITECTURE "avr32"
 #elif defined(__m32r__)
 #define _PR_SI_ARCHITECTURE "m32r"
+#elif defined(__nios2__)
+#define _PR_SI_ARCHITECTURE "nios2"
 #elif defined(__or1k__)
 #define _PR_SI_ARCHITECTURE "or1k"
 #else
@@ -125,6 +127,18 @@ extern PRInt32 _PR_x86_64_AtomicSet(PRInt32 *val, PRInt32 newval);
 #define _MD_ATOMIC_SET                _PR_x86_64_AtomicSet
 #endif
 
+#if defined(__nios2__)
+#if defined(__GNUC__)
+/* Use GCC built-in functions */
+#define _PR_HAVE_ATOMIC_OPS
+#define _MD_INIT_ATOMIC()
+#define _MD_ATOMIC_INCREMENT(ptr) __sync_add_and_fetch(ptr, 1)
+#define _MD_ATOMIC_DECREMENT(ptr) __sync_sub_and_fetch(ptr, 1)
+#define _MD_ATOMIC_ADD(ptr, i) __sync_add_and_fetch(ptr, i)
+#define _MD_ATOMIC_SET(ptr, nv) __sync_lock_test_and_set(ptr, nv)
+#endif
+#endif
+
 #if defined(__or1k__)
 #if defined(__GNUC__)
 /* Use GCC built-in functions */
EOF
}

add_automatic nss

buildenv_openldap() {
	export ol_cv_pthread_select_yields=yes
	export ac_cv_func_memcmp_working=yes
}

add_automatic openssl
add_automatic openssl1.0
add_automatic p11-kit
add_automatic patch
add_automatic pcre2

add_automatic pcre3
patch_pcre3() {
	echo "work around FTBFS with gcc-8 #897834"
	# ignore symbol changes
	sed -i -e 's/\(dh_makeshlibs.*-- -c\)4$/\10/' debian/rules
}

add_automatic popt

builddep_readline() {
	assert_built "ncurses"
	# gcc-multilib dependency unsatisfiable
	$APT_GET install debhelper "libtinfo-dev:$1" "libncursesw5-dev:$1" mawk texinfo autotools-dev
	case "$ENABLE_MULTILIB:$HOST_ARCH" in
		yes:amd64|yes:ppc64)
			test "$1" = "$HOST_ARCH"
			$APT_GET install "gcc-$GCC_VER-multilib$HOST_ARCH_SUFFIX" "lib32tinfo-dev:$1" "lib32ncursesw5-dev:$1"
			# the unversioned gcc-multilib$HOST_ARCH_SUFFIX should contain the following link
			ln -sf "`dpkg-architecture -a$1 -qDEB_HOST_MULTIARCH`/asm" /usr/include/asm
		;;
		yes:i386|yes:powerpc|yes:sparc|yes:s390)
			test "$1" = "$HOST_ARCH"
			$APT_GET install "gcc-$GCC_VER-multilib$HOST_ARCH_SUFFIX" "lib64ncurses5-dev:$1"
			# the unversioned gcc-multilib$HOST_ARCH_SUFFIX should contain the following link
			ln -sf "`dpkg-architecture -a$1 -qDEB_HOST_MULTIARCH`/asm" /usr/include/asm
		;;
	esac
}
patch_readline() {
	echo "patching readline to support nobiarch profile #737955"
	drop_privs patch -p1 <<EOF
--- a/debian/control
+++ b/debian/control
@@ -4,10 +4,10 @@
 Maintainer: Matthias Klose <doko@debian.org>
 Standards-Version: 4.3.0
 Build-Depends: debhelper (>= 9),
   libncurses-dev,
-  lib32ncurses-dev [amd64 ppc64], lib64ncurses-dev [i386 powerpc sparc s390],
+  lib32ncurses-dev [amd64 ppc64] <!nobiarch>, lib64ncurses-dev [i386 powerpc sparc s390] <!nobiarch>,
   mawk | awk, texinfo, autotools-dev,
-  gcc-multilib [amd64 i386 kfreebsd-amd64 powerpc ppc64 s390 sparc]
+  gcc-multilib [amd64 i386 kfreebsd-amd64 powerpc ppc64 s390 sparc] <!nobiarch>
 
 Package: libreadline8
 Architecture: any
@@ -30,6 +30,7 @@
 Depends: readline-common, \${shlibs:Depends}, \${misc:Depends}
 Section: libs
 Priority: optional
+Build-Profiles: <!nobiarch>
 Description: GNU readline and history libraries, run-time libraries (64-bit)
  The GNU readline library aids in the consistency of user interface
  across discrete programs that need to provide a command line
@@ -96,6 +97,7 @@
 Conflicts: lib64readline-dev, lib64readline-gplv2-dev
 Section: libdevel
 Priority: optional
+Build-Profiles: <!nobiarch>
 Description: GNU readline and history libraries, development files (64-bit)
  The GNU readline library aids in the consistency of user interface
  across discrete programs that need to provide a command line
@@ -139,6 +141,7 @@
 Depends: readline-common, \${shlibs:Depends}, \${misc:Depends}
 Section: libs
 Priority: optional
+Build-Profiles: <!nobiarch>
 Description: GNU readline and history libraries, run-time libraries (32-bit)
  The GNU readline library aids in the consistency of user interface
  across discrete programs that need to provide a command line
@@ -154,6 +157,7 @@
 Conflicts: lib32readline-dev, lib32readline-gplv2-dev
 Section: libdevel
 Priority: optional
+Build-Profiles: <!nobiarch>
 Description: GNU readline and history libraries, development files (32-bit)
  The GNU readline library aids in the consistency of user interface
  across discrete programs that need to provide a command line
--- a/debian/rules
+++ b/debian/rules
@@ -57,6 +57,11 @@
   endif
 endif
 
+ifneq (\$(filter nobiarch,\$(DEB_BUILD_PROFILES)),)
+build32 =
+build64 =
+endif
+
 CFLAGS := \$(shell dpkg-buildflags --get CFLAGS)
 CPPFLAGS := \$(shell dpkg-buildflags --get CPPFLAGS)
 LDFLAGS := \$(shell dpkg-buildflags --get LDFLAGS)
EOF
	echo "fix misbuild #932023"
	drop_privs patch -p1 <<'EOF'
--- readline-8.0/debian/control
+++ readline-8.0/debian/control
@@ -94,6 +94,7 @@
 Section: utils
 Priority: optional
 Provides: readline-editor
+Build-Profiles: <!cross>
 Description: Front-end using readline to "cook" input lines for other programs
  This tool lets you use history and line-editing in any text oriented
  tool. This is especially useful with third-party proprietary tools that
--- readline-8.0/debian/rules
+++ readline-8.0/debian/rules
@@ -395,7 +391,6 @@
 		examples/Inputrc
 	ln -sf $(p_rl) $(d_rld)/usr/share/doc/$(p_rld)

-ifeq ($(DEB_HOST_GNU_TYPE),$(DEB_BUILD_GNU_TYPE))
 	dh_installdocs -p$(p_rlfe) examples/rlfe/README
 	dh_installchangelogs -p$(p_rlfe) examples/rlfe/ChangeLog

@@ -407,7 +402,6 @@
 	cp -p debian/libreadline.shlibs debian/shlibs.local
 	dh_shlibdeps -p$(p_rl) -p$(p_rld) -p$(p_rlfe) \
 		 -L $(p_rl) -l $(d_rl)/lib
-endif

 ifneq ($(build32),)
 	-ls -l $(d_rld)/usr/share/doc/$(p_rl)
EOF
}

add_automatic readline5
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
}

add_automatic tcltk-defaults
add_automatic tcp-wrappers

add_automatic tk8.6
buildenv_tk8_6() {
	export tcl_cv_strtod_buggy=ok
}

add_automatic uchardet
add_automatic ustr

builddep_util_linux() {
	dpkg-architecture "-a$1" -ilinux-any && assert_built libselinux
	assert_built "ncurses slang2 zlib"
	$APT_GET build-dep "-a$1" --arch-only -P "$2" util-linux
}
buildenv_util_linux() {
	export scanf_cv_type_modifier=ms
}

add_automatic xft
add_automatic xz-utils

builddep_zlib() {
	# gcc-multilib dependency unsatisfiable
	$APT_GET install debhelper binutils dpkg-dev
}

# choosing libatomic1 arbitrarily here, cause it never bumped soname
BUILD_GCC_MULTIARCH_VER=`apt-cache show --no-all-versions libatomic1 | sed 's/^Source: gcc-\([0-9.]*\)$/\1/;t;d'`
if test "$GCC_VER" != "$BUILD_GCC_MULTIARCH_VER"; then
	echo "host gcc version ($GCC_VER) and build gcc version ($BUILD_GCC_MULTIARCH_VER) mismatch. need different build gcc"
if dpkg --compare-versions "$GCC_VER" gt "$BUILD_GCC_MULTIARCH_VER"; then
	echo "deb [ arch=$(dpkg --print-architecture) ] $MIRROR experimental main" > /etc/apt/sources.list.d/tmp-experimental.list
	$APT_GET update
	$APT_GET -t experimental install g++ g++-$GCC_VER
	rm -f /etc/apt/sources.list.d/tmp-experimental.list
	$APT_GET update
elif test -f "$REPODIR/stamps/gcc_0"; then
	echo "skipping rebuild of build gcc"
	$APT_GET --force-yes dist-upgrade # downgrade!
else
	$APT_GET build-dep --arch-only gcc-$GCC_VER
	# dependencies for common libs no longer declared
	$APT_GET install doxygen graphviz ghostscript texlive-latex-base xsltproc docbook-xsl-ns
	cross_build_setup "gcc-$GCC_VER" gcc0
	(
		export gcc_cv_libc_provides_ssp=yes
		nolang=$(set_add "${GCC_NOLANG:-}" biarch)
		export DEB_BUILD_OPTIONS="$DEB_BUILD_OPTIONS nolang=$(join_words , $nolang)"
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
	$APT_GET install binutils$HOST_ARCH_SUFFIX
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
	drop_privs TARGET=hppa64-linux-gnu dpkg-buildpackage -B -Pnocheck --target=stamps/control
	drop_privs TARGET=hppa64-linux-gnu dpkg-buildpackage -B -uc -us -Pnocheck
	cd ..
	ls -l
	pickup_additional_packages binutils-hppa64-linux-gnu_*.deb
	$APT_GET install binutils-hppa64-linux-gnu
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
	$APT_GET install debhelper sharutils autoconf automake texinfo
	cross_build_setup gnumach gnumach_1
	drop_privs dpkg-buildpackage -B "-a$HOST_ARCH" -Pstage1 -uc -us
	cd ..
	pickup_packages ./*.deb
	touch "$REPODIR/stamps/gnumach_1"
	cd ..
	drop_privs rm -Rf gnumach_1
fi
progress_mark "gnumach stage1 cross build"
fi

if test "$(dpkg-architecture "-a$HOST_ARCH" -qDEB_HOST_ARCH_OS)" = kfreebsd; then
cross_build kfreebsd-kernel-headers
fi

if test -f "$REPODIR/stamps/gcc_1"; then
	echo "skipping rebuild of gcc stage1"
else
	apt_get_install debhelper gawk patchutils bison flex lsb-release quilt libtool autoconf2.64 zlib1g-dev libmpc-dev libmpfr-dev libgmp-dev autogen systemtap-sdt-dev sharutils "binutils$HOST_ARCH_SUFFIX"
	if test "$(dpkg-architecture "-a$HOST_ARCH" -qDEB_HOST_ARCH_OS)" = linux; then
		if test "$ENABLE_MULTIARCH_GCC" = yes; then
			apt_get_install "linux-libc-dev:$HOST_ARCH"
		else
			apt_get_install "linux-libc-dev-${HOST_ARCH}-cross"
		fi
	fi
	if test "$HOST_ARCH" = hppa; then
		$APT_GET install binutils-hppa64-linux-gnu
	fi
	cross_build_setup "gcc-$GCC_VER" gcc1
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
		$APT_GET install "gcc-$GCC_VER-multilib$HOST_ARCH_SUFFIX"
	else
		rm -vf ./*multilib*.deb
		$APT_GET install "gcc-$GCC_VER$HOST_ARCH_SUFFIX"
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
	apt_get_install texinfo debhelper dh-exec autoconf dh-autoreconf gawk flex bison autotools-dev perl
	cross_build_setup hurd hurd_1
	dpkg-checkbuilddeps -B "-a$HOST_ARCH" -Pstage1 || :
	drop_privs dpkg-buildpackage -d -B "-a$HOST_ARCH" -Pstage1 -uc -us
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
	apt_get_install dpkg-dev debhelper "gnumach-dev:$HOST_ARCH" flex libfl-dev bison dh-autoreconf
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

if test -f "$REPODIR/stamps/${LIBC_NAME}_1"; then
	echo "skipping rebuild of $LIBC_NAME stage1"
else
	cross_build_setup "$LIBC_NAME" "${LIBC_NAME}_1"
	if test "$LIBC_NAME" = glibc; then
		"$(get_hook builddep glibc)" "$HOST_ARCH" stage1
	else
		apt_get_build_dep "-a$HOST_ARCH" --arch-only ./
	fi
	if test "$ENABLE_MULTILIB" = yes; then
		dpkg-checkbuilddeps -B "-a$HOST_ARCH" -Pstage1 || : # tell unmet build depends
		drop_privs DEB_GCC_VERSION="-$GCC_VER" dpkg-buildpackage -B -uc -us "-a$HOST_ARCH" -d -Pstage1
	else
		dpkg-checkbuilddeps -B "-a$HOST_ARCH" -Pstage1,nobiarch || : # tell unmet build depends
		drop_privs DEB_GCC_VERSION="-$GCC_VER" dpkg-buildpackage -B -uc -us "-a$HOST_ARCH" -d -Pstage1,nobiarch
	fi
	cd ..
	ls -l
	apt_get_remove libc6-dev-i386
	if test "$ENABLE_MULTIARCH_GCC" = yes; then
		if test "$(dpkg-architecture "-a$HOST_ARCH" -qDEB_HOST_ARCH_OS)" = linux; then
			$APT_GET install "linux-libc-dev:$HOST_ARCH"
		fi
		pickup_packages *.changes
		if test "$LIBC_NAME" = musl; then
			dpkg -i musl*.deb
		else
			dpkg -i libc*.deb
		fi
	else
		if test "$(dpkg-architecture "-a$HOST_ARCH" -qDEB_HOST_ARCH_OS)" = linux; then
			$APT_GET install "linux-libc-dev-$HOST_ARCH-cross"
		fi
		for pkg in *.deb; do
			drop_privs dpkg-cross -M -a "$HOST_ARCH" -X tzdata -X libc-bin -X libc-dev-bin -b "$pkg"
		done
		pickup_packages *.changes *-cross_*.deb
		dpkg -i libc*-cross_*.deb
	fi
	touch "$REPODIR/stamps/${LIBC_NAME}_1"
	cd ..
	drop_privs rm -Rf "${LIBC_NAME}_1"
fi
progress_mark "$LIBC_NAME stage1 cross build"

# dpkg happily breaks depends when upgrading build arch multilibs to host arch multilibs
apt_get_remove $(dpkg-query -W "lib*gcc*:$(dpkg --print-architecture)" | sed "s/\\s.*//;/:$(dpkg --print-architecture)/d")

if test "$LIBC_NAME" != musl; then

if test -f "$REPODIR/stamps/gcc_2"; then
	echo "skipping rebuild of gcc stage2"
else
	apt_get_install debhelper gawk patchutils bison flex lsb-release quilt libtool autoconf2.64 zlib1g-dev libmpc-dev libmpfr-dev libgmp-dev autogen systemtap-sdt-dev sharutils "binutils$HOST_ARCH_SUFFIX"
	if test "$ENABLE_MULTIARCH_GCC" = yes -o "$LIBC_NAME" != glibc; then
		apt_get_install "libc-dev:$HOST_ARCH"
	else
		apt_get_install "libc6-dev-${HOST_ARCH}-cross"
	fi
	if test "$HOST_ARCH" = hppa; then
		$APT_GET install binutils-hppa64-linux-gnu
	fi
	cross_build_setup "gcc-$GCC_VER" gcc2
	dpkg-checkbuilddeps -a$HOST_ARCH || : # tell unmet build depends
	echo "$HOST_ARCH" > debian/target
	(
		export DEB_STAGE=stage2
		nolang=${GCC_NOLANG:-}
		test "$ENABLE_MULTILIB" = yes || nolang=$(set_add "$nolang" biarch)
		export DEB_BUILD_OPTIONS="$DEB_BUILD_OPTIONS${nolang:+ nolang=$(join_words , $nolang)}"
		if test "$ENABLE_MULTIARCH_GCC" = yes; then
			export with_deps_on_target_arch_pkgs=yes
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
	drop_privs rm -vf ./*multilib*.deb
	dpkg -i *.deb
	compiler="`dpkg-architecture -a$HOST_ARCH -qDEB_HOST_GNU_TYPE`-gcc-$GCC_VER"
	if ! which "$compiler"; then echo "$compiler missing in stage2 gcc package"; exit 1; fi
	if ! drop_privs "$compiler" -x c -c /dev/null -o test.o; then echo "stage2 gcc fails to execute"; exit 1; fi
	if ! test -f test.o; then echo "stage2 gcc fails to create binaries"; exit 1; fi
	check_arch test.o "$HOST_ARCH"
	touch "$REPODIR/stamps/gcc_2"
	cd ..
	drop_privs rm -Rf gcc2
fi
progress_mark "cross gcc stage2 build"

if test "$(dpkg-architecture "-a$HOST_ARCH" -qDEB_HOST_ARCH_OS)" = hurd; then
if test -f "$REPODIR/stamps/hurd_2"; then
	echo "skipping rebuild of hurd stage2"
else
	apt_get_install texinfo debhelper dh-exec autoconf dh-autoreconf gawk flex bison autotools-dev "libc-dev:$HOST_ARCH" perl
	cross_build_setup hurd hurd_2
	dpkg-checkbuilddeps -B "-a$HOST_ARCH" -Pstage2 || :
	drop_privs dpkg-buildpackage -d -B "-a$HOST_ARCH" -Pstage2 -uc -us
	cd ..
	ls -l
	pickup_packages *.changes
	touch "$REPODIR/stamps/hurd_2"
	cd ..
	drop_privs rm -Rf hurd_2
fi
progress_mark "hurd stage2 cross build"
fi

# several undeclared file conflicts such as #745552 or #784015
apt_get_remove $(dpkg-query -W "libc[0-9]*:$(dpkg --print-architecture)" | sed "s/\\s.*//;/:$(dpkg --print-architecture)/d")

if test -f "$REPODIR/stamps/${LIBC_NAME}_2"; then
	echo "skipping rebuild of $LIBC_NAME stage2"
else
	cross_build_setup "$LIBC_NAME" "${LIBC_NAME}_2"
	if test "$LIBC_NAME" = glibc; then
		"$(get_hook builddep glibc)" "$HOST_ARCH" stage2
	else
		apt_get_build_dep "-a$HOST_ARCH" --arch-only ./
	fi
	if test "$ENABLE_MULTILIB" = yes; then
		dpkg-checkbuilddeps -B "-a$HOST_ARCH" -Pstage2 || : # tell unmet build depends
		drop_privs DEB_GCC_VERSION=-$GCC_VER dpkg-buildpackage -B -uc -us "-a$HOST_ARCH" -d -Pstage2
	else
		dpkg-checkbuilddeps -B "-a$HOST_ARCH" -Pstage2,nobiarch || : # tell unmet build depends
		drop_privs DEB_GCC_VERSION=-$GCC_VER dpkg-buildpackage -B -uc -us "-a$HOST_ARCH" -d -Pstage2,nobiarch
	fi
	cd ..
	ls -l
	if test "$ENABLE_MULTIARCH_GCC" = yes; then
		pickup_packages *.changes
		$APT_GET dist-upgrade
	else
		for pkg in libc[0-9]*.deb; do
			# dpkg-cross cannot handle these
			test "${pkg%%_*}" = "libc6-i686" && continue
			test "${pkg%%_*}" = "libc6-loongson2f" && continue
			test "${pkg%%_*}" = "libc6-xen" && continue
			test "${pkg%%_*}" = "libc6.1-alphaev67" && continue
			drop_privs dpkg-cross -M -a "$HOST_ARCH" -X tzdata -X libc-bin -X libc-dev-bin -X multiarch-support -b "$pkg"
		done
		pickup_packages *.changes *-cross_*.deb
		$APT_GET dist-upgrade
	fi
	touch "$REPODIR/stamps/${LIBC_NAME}_2"
	compare_native ./*.deb
	cd ..
	drop_privs rm -Rf "${LIBC_NAME}_2"
fi
progress_mark "$LIBC_NAME stage2 cross build"

fi # $LIBC_NAME != musl

if test -f "$REPODIR/stamps/gcc_3"; then
	echo "skipping rebuild of gcc stage3"
else
	apt_get_install debhelper gawk patchutils bison flex lsb-release quilt libtool autoconf2.64 zlib1g-dev libmpc-dev libmpfr-dev libgmp-dev dejagnu autogen systemtap-sdt-dev sharutils "binutils$HOST_ARCH_SUFFIX"
	if test "$HOST_ARCH" = hppa; then
		$APT_GET install binutils-hppa64-linux-gnu
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
	apt_get_install debhelper gawk patchutils bison flex lsb-release quilt libtool autoconf2.64 zlib1g-dev libmpc-dev libmpfr-dev libgmp-dev dejagnu autogen systemtap-sdt-dev sharutils "binutils$HOST_ARCH_SUFFIX" "libc-dev:$HOST_ARCH"
	if test "$HOST_ARCH" = hppa; then
		$APT_GET install binutils-hppa64-linux-gnu
	fi
	if test "$ENABLE_MULTILIB" = yes -a -n "$MULTILIB_NAMES"; then
		$APT_GET install $(echo $MULTILIB_NAMES | sed "s/\(\S\+\)/libc6-dev-\1-$HOST_ARCH-cross libc6-dev-\1:$HOST_ARCH/g")
	fi
	cross_build_setup "gcc-$GCC_VER" gcc_f1
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
if test -f "$REPODIR/stamps/hurd_3"; then
	echo "skipping rebuild of hurd stage3"
else
	apt_get_install "gnumach-dev:$HOST_ARCH" "libc0.3-dev:$HOST_ARCH" texinfo debhelper dpkg-dev dh-exec autoconf dh-autoreconf gawk flex bison autotools-dev
	cross_build_setup hurd hurd_3
	dpkg-checkbuilddeps -B "-a$HOST_ARCH" -Pstage3 || : # gcc-5 dependency unsatisfiable
	drop_privs dpkg-buildpackage -d -B "-a$HOST_ARCH" -Pstage3 -uc -us
	cd ..
	ls -l
	pickup_packages *.changes
	touch "$REPODIR/stamps/hurd_3"
	cd ..
	drop_privs rm -Rf hurd_3
fi
apt_get_install "hurd-dev:$HOST_ARCH"
progress_mark "hurd stage3 cross build"
fi

$APT_GET install dose-builddebcheck dctrl-tools

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
	apt-cache show "gcc-${GCC_VER}-base=installed" libgcc1=installed libstdc++6=installed libatomic1=installed >> "$package_list" # helps when pulling gcc from experimental
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
add_need attr # by coreutils, libcap-ng
add_need autogen # by gcc-VER, gnutls28
add_need blt # by pythonX.Y
add_need bsdmainutils # for man-db
add_need bzip2 # by perl
add_need db-defaults # by perl, python2.7, python3.5
add_need elfutils # by glib2.0
add_need expat # by unbound
add_need file # by gcc-6, for debhelper
add_need flex # by libsemanage, pam
dpkg-architecture "-a$HOST_ARCH" -ikfreebsd-any && add_need freebsd-glue # by freebsd-libs
add_need fribidi # by newt
add_need gnupg2 # for apt
add_need gnutls28 # by libprelude, openldap
test "$(dpkg-architecture "-a$HOST_ARCH" -qDEB_HOST_ARCH_OS)" = linux && add_need gpm # by ncurses
add_need groff # for man-db
test "$(dpkg-architecture "-a$HOST_ARCH" -qDEB_HOST_ARCH_OS)" = linux && add_need kmod # by systemd
add_need icu # by libxml2
add_need krb5 # by audit
add_need libatomic-ops # by gcc-VER
dpkg-architecture "-a$HOST_ARCH" -ilinux-any && add_need libcap2 # by systemd
add_need libdebian-installer # by cdebconf
add_need libevent # by unbound
add_need libgcrypt20 # by libprelude, cryptsetup
dpkg-architecture "-a$HOST_ARCH" -ilinux-any && add_need libsepol # by libselinux
if dpkg-architecture "-a$HOST_ARCH" -ihurd-any || dpkg-architecture "-a$HOST_ARCH" -ikfreebsd-any; then
	add_need libsystemd-dummy # by nghttp2
fi
add_need libtextwrap # by cdebconf
add_need libx11 # by dbus
add_need libxrender # by cairo
add_need libzstd # by apt
add_need lz4 # by systemd
add_need make-dfsg # for build-essential
add_need man-db # for debhelper
add_need mawk # for base-files (alternatively: gawk)
add_need mpclib3 # by gcc-VER
add_need mpdecimal # by python3.X
add_need mpfr4 # by gcc-VER
add_need nettle # by unbound
add_need openssl # by cyrus-sasl2
add_need patch # for dpkg-dev
add_need pcre2 # by libselinux
add_need popt # by newt
add_need readline5 # by lvm2
add_need slang2 # by cdebconf, newt
add_need sqlite3 # by python2.7
add_need tcl8.6 # by newt
add_need tcltk-defaults # by python2.7
dpkg-architecture "-a$HOST_ARCH" -ilinux-any && add_need tcp-wrappers # by audit
add_need xz-utils # by libxml2

automatically_cross_build_packages() {
	local need_packages_comma_sep dosetmp profiles buildable new_needed line pkg missing source
	while test -n "$need_packages"; do
		echo "checking packages with dose-builddebcheck: $need_packages"
		need_packages_comma_sep=`echo $need_packages | sed 's/ /,/g'`
		dosetmp=`mktemp -t doseoutput.XXXXXXXXXX`
		profiles="$DEFAULT_PROFILES"
		if test "$ENABLE_MULTILIB" = no; then
			profiles=$(set_add "$profiles" nobiarch)
		fi
		profiles=$(echo "$profiles" | tr ' ' ,)
		call_dose_builddebcheck --successes --failures --explain --latest=1 --deb-drop-b-d-indep "--deb-profiles=$profiles" "--checkonly=$need_packages_comma_sep" >"$dosetmp"
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
	local missing_pkgs missing_pkgs_comma_sep profiles
	missing_pkgs=`set_difference "$1" "$built_packages"`
	test -z "$missing_pkgs" && return 0
	echo "rebootstrap-error: missing asserted packages: $missing_pkgs"
	missing_pkgs=`set_union "$missing_pkgs" "$need_packages"`
	missing_pkgs_comma_sep=`echo $missing_pkgs | sed 's/ /,/g'`
	profiles="$DEFAULT_PROFILES"
	if test "$ENABLE_MULTILIB" = no; then
		profiles=$(set_add "$profiles" nobiarch)
	fi
	profiles=$(echo "$profiles" | tr ' ' ,)
	call_dose_builddebcheck --failures --explain --latest=1 --deb-drop-b-d-indep "--deb-profiles=$profiles" "--checkonly=$missing_pkgs_comma_sep"
	return 1
}

automatically_cross_build_packages

cross_build zlib "$(if test "$ENABLE_MULTILIB" != yes; then echo stage1; fi)"
mark_built zlib
# needed by dpkg, file, gnutls28, libpng1.6, libtool, libxml2, perl, slang2, tcl8.6, util-linux

automatically_cross_build_packages

cross_build libtool
mark_built libtool
# needed by guile-2.0, libffi

automatically_cross_build_packages

cross_build ncurses
mark_built ncurses
# needed by bash, bsdmainutils, dpkg, guile-2.0, readline, slang2

automatically_cross_build_packages

cross_build readline
mark_built readline
# needed by gnupg2, guile-2.0, libxml2

automatically_cross_build_packages

if dpkg-architecture "-a$HOST_ARCH" -ilinux-any; then
	assert_built "libsepol pcre2"
	cross_build libselinux "nopython noruby" libselinux_1
	mark_built libselinux
# needed by coreutils, dpkg, findutils, glibc, sed, tar, util-linux

automatically_cross_build_packages
fi # $HOST_ARCH matches linux-any

cross_build util-linux stage1 util-linux_1
mark_built util-linux
# essential, needed by e2fsprogs

automatically_cross_build_packages

cross_build db5.3 "pkg.db5.3.notcl nojava" db5.3_1
mark_built db5.3
# needed by perl, python2.7, needed for db-defaults and thus by freebsd-glue

automatically_cross_build_packages

cross_build libxml2 nopython libxml2_1
mark_built libxml2
# needed by autogen

automatically_cross_build_packages

if test -f "$REPODIR/stamps/cracklib2_1"; then
	echo "skipping stage1 rebuild of cracklib2"
else
	cross_build_setup cracklib2 cracklib2_1
	# explicitly disable zlib support #928436
	apt_get_remove "zlib1g-dev:$(dpkg --print-architecture)" "zlib1g-dev:$HOST_ARCH"
	apt_get_build_dep "-a$HOST_ARCH" --arch-only -Pcross,nopython ./
	check_binNMU
	drop_privs dpkg-buildpackage "-a$HOST_ARCH" -B -Pcross,nopython -uc -us
	cd ..
	ls -l
	pickup_packages *.changes
	touch "$REPODIR/stamps/cracklib2_1"
	compare_native ./*.deb
	cd ..
	drop_privs rm -Rf cracklib2_1
fi
progress_mark "cracklib2 stage1 cross build"
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

if test -f "$REPODIR/stamps/cyrus-sasl2_1"; then
	echo "skipping stage1 rebuild of cyrus-sasl2"
else
	builddep_cyrus_sasl2 "$HOST_ARCH"
	cross_build_setup cyrus-sasl2 cyrus-sasl2_1
	check_binNMU
	dpkg-checkbuilddeps -B "-a$HOST_ARCH" || : # tell unmet build depends
	drop_privs DEB_BUILD_OPTIONS="$DEB_BUILD_OPTIONS no-sql no-ldap no-gssapi" dpkg-buildpackage "-a$HOST_ARCH" -B -d -uc -us
	cd ..
	ls -l
	pickup_packages *.changes
	touch "$REPODIR/stamps/cyrus-sasl2_1"
	compare_native ./*.deb
	cd ..
	drop_privs rm -Rf cyrus-sasl2_1
fi
progress_mark "cyrus-sasl2 stage1 cross build"
mark_built cyrus-sasl2
# needed by openldap

automatically_cross_build_packages

assert_built "libevent expat nettle"
dpkg-architecture "-a$HOST_ARCH" -ilinux-any || assert_built libbsd
cross_build unbound pkg.unbound.libonly unbound_1
mark_built unbound
# needed by gnutls28

automatically_cross_build_packages

assert_built "gnutls28 cyrus-sasl2"
cross_build openldap stage1 openldap_1
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

if test -f "$REPODIR/stamps/systemd_1"; then
	echo "skipping stage1 rebuild of systemd"
else
	cross_build_setup systemd systemd_1
	assert_built "libcap2 pam libselinux acl xz-utils libgcrypt20 kmod util-linux"
	if grep -q "^Build-Depends:.*libseccomp-dev[^,]*[[ ]$HOST_ARCH[] ]" debian/control; then
		assert_built libseccomp
	fi
	apt_get_build_dep "-a$HOST_ARCH" --arch-only -P nocheck,noudeb,stage1 ./
	check_binNMU
	drop_privs dpkg-buildpackage "-a$HOST_ARCH" -B -uc -us -Pnocheck,noudeb,stage1 -d
	cd ..
	ls -l
	pickup_packages *.changes
	touch "$REPODIR/stamps/systemd_1"
	compare_native ./*.deb
	cd ..
	drop_privs rm -Rf systemd_1
fi
progress_mark "systemd stage1 cross build"
mark_built systemd
# needed by util-linux

automatically_cross_build_packages

assert_built attr
cross_build libcap-ng nopython libcap-ng_1
mark_built libcap-ng
# needed by audit, dbus

automatically_cross_build_packages

assert_built "gnutls28 libgcrypt20 libtool"
cross_build libprelude "nolua noperl nopython noruby" libprelude_1
mark_built libprelude
# needed by audit, dbus

automatically_cross_build_packages

cross_build glib2.0
mark_built glib2.0
# needed by libverto, libxt

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

cross_build util-linux # stageless
# essential

automatically_cross_build_packages

cross_build apt
mark_built apt
# almost essential

automatically_cross_build_packages

if test -f "$REPODIR/stamps/gdbm_1"; then
	echo "skipping rebuild of gdbm stage1"
else
	cross_build_setup gdbm gdbm_1
	apt_get_build_dep --arch-only "-a$HOST_ARCH" -P pkg.gdbm.nodietlibc ./
	check_binNMU
	(
		buildenv_gdbm "$HOST_ARCH"
		drop_privs dpkg-buildpackage "-a$HOST_ARCH" -B -uc -us -Ppkg.gdbm.nodietlibc
	)
	cd ..
	ls -l
	pickup_packages *.changes
	touch "$REPODIR/stamps/gdbm_1"
	compare_native ./*.deb
	cd ..
	drop_privs rm -Rf gdbm_1
fi
progress_mark "gdbm stage1 cross build"
mark_built gdbm
# needed by man-db, perl, python2.7

automatically_cross_build_packages

if test -f "$REPODIR/stamps/newt_1"; then
	echo "skipping rebuild of newt stage1"
else
	cross_build_setup newt newt_1
	apt_get_build_dep "-a$HOST_ARCH" --arch-only -P stage1 ./
	check_binNMU
	drop_privs dpkg-buildpackage "-a$HOST_ARCH" -B -uc -us -Pstage1
	cd ..
	ls -l
	pickup_packages *.changes
	touch "$REPODIR/stamps/newt_1"
	compare_native ./*.deb
	cd ..
	drop_privs rm -Rf newt_1
fi
progress_mark "newt stage1 cross build"
mark_built newt
# needed by cdebconf

automatically_cross_build_packages

if test -f "$REPODIR/stamps/cdebconf_1"; then
	echo "skipping rebuild of cdebconf nogtk"
else
	cross_build_setup cdebconf cdebconf_1
	apt_get_build_dep "-a$HOST_ARCH" --arch-only -P pkg.cdebconf.nogtk ./
	check_binNMU
	drop_privs dpkg-buildpackage "-a$HOST_ARCH" -B -uc -us -Ppkg.cdebconf.nogtk
	cd ..
	ls -l
	pickup_packages *.changes
	touch "$REPODIR/stamps/cdebconf_1"
	compare_native ./*.deb
	cd ..
	drop_privs rm -Rf cdebconf_1
fi
progress_mark "cdebconf nogtk cross build"
mark_built cdebconf
# needed by base-passwd

automatically_cross_build_packages

assert_built "$need_packages"

echo "checking installability of build-essential with dose"
apt_get_install botch
package_list=$(mktemp -t packages.XXXXXXXXXX)
grep-dctrl --exact --field Architecture '(' "$HOST_ARCH" --or all ')' /var/lib/apt/lists/*_Packages > "$package_list"
botch-distcheck-more-problems "--deb-native-arch=$HOST_ARCH" --successes --failures --explain --checkonly "build-essential:$HOST_ARCH" "--bg=deb://$package_list" "--fg=deb://$package_list" || :
rm -f "$package_list"
