#! /bin/sh
#
# Copyright (c) 2025 SHENGYI HUNG
# All rights reserved.
#
# Redistribution and use in source and binary forms, with or without
# modification, are permitted provided that the following conditions
# are met:
# 1. Redistributions of source code must retain the above copyright
#    notice, this list of conditions and the following disclaimer 
#    in this position and unchanged.
# 2. Redistributions in binary form must reproduce the above copyright
#    notice, this list of conditions and the following disclaimer in the
#    documentation and/or other materials provided with the distribution.
# 3. The name of the author may not be used to endorse or promote products
#    derived from this software without specific prior written permission
#
# THIS SOFTWARE IS PROVIDED BY THE AUTHOR ``AS IS'' AND ANY EXPRESS OR
# IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE IMPLIED WARRANTIES
# OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE ARE DISCLAIMED.
# IN NO EVENT SHALL THE AUTHOR BE LIABLE FOR ANY DIRECT, INDIRECT,
# INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL DAMAGES (INCLUDING, BUT
# NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS OR SERVICES; LOSS OF USE,
# DATA, OR PROFITS; OR BUSINESS INTERRUPTION) HOWEVER CAUSED AND ON ANY
# THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT LIABILITY, OR TORT
# (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY OUT OF THE USE OF
# THIS SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF SUCH DAMAGE.
#

default_version="14.1-RELEASE"
default_download_root="https://download.freebsd.org/ftp/releases"
default_obj_root="/usr/obj/usr/src"
default_arch=`uname -p`

usage() {
	echo "usage: diff.sh -a <arch> -v <base_version> -d <download_root> -o <obj_root> <type>"
	echo "default values:"
	echo "arch: $default_arch"
	echo "base_version:" $default_version
	echo "download_root:" $default_download_root
	echo "obj_root:" $default_obj_root
	echo "type: base, kernel, and lib32"

	exit 1
}

version=$default_version
download_root=$default_download_root
obj_root=$default_obj_root
obj_dir=""
fetched_dir=""

arch=$default_arch
processor_arch=""

while getopts "a:v:d:o:p:" opt
do
	case "$opt" in
		a) arch="$OPTARG";;
		v) version="$OPTARG";;
		d) download_root="$OPTARG";;
		o) obj_root="$OPTARG";;
		p) processor_arch="$OPTARG";;
		*) usage;;
	esac
done

shift $((OPTIND-1))
tarball_class=$@

if [ "$processor_arch" = "" ]; then
	case "$arch" in
		amd64) processor_arch="amd64";;
		arm) processor_arch="armv7";;
		arm64) processor_arch="aarch64";;
		i386) processor_arch="i386";;
		powerpc) processor_arch="powerpc64";;
		ricsv) processor_arch="riscv64";;
		*) usage;;
	esac
fi

case "$tarball_class" in
	base) ;;
	kernel) obj_dir="sys/GENERIC"; fetched_dir="boot/kernel";;
	lib32) ;;
	*) echo "unsupported tarball class: $tarball_class"; usage ;;
esac

download_url_processor_arch=""

if [ "$arch" != "$processor_arch" ]; then
	download_url_processor_arch="/"$processor_arch
fi

obj_diff_dir=$obj_root"/"$arch"."$processor_arch"/"$obj_dir

if [ ! -d $obj_diff_dir ]; then
	echo "Compilation artifact directory $obj_diff_dir not found"
	exit 1
fi

# start fetching binary
download_url=$download_root"/"$arch$download_url_processor_arch"/"$version"/"$tarball_class".txz"
echo "Download tarball at: $download_url"
tarball_dir=`mktemp -d`
tarball_path=$tarball_dir"/"$tarball_class".txz"

fetch $download_url -o $tarball_path

if [ $? -ne 0 ]; then
	echo "Unable to fetch the tarball"
fi

tar -xf $tarball_path -C $tarball_dir

if [ $? -ne 0 ]; then
	echo "Unable to unzip the tarball"
fi

fetched_diff_dir=$tarball_dir"/"$fetched_dir

for fetched_file in `find $fetched_diff_dir -type f`; do
	# In ELF format, the first four bytes are "0x7f454c46", that is, "DEL"ELF in ascii code.
	# To be more clear, we only check if "ELF" appear in binary
	if [ "`stat -f %z $fetched_file `" -le 3 ] || [ "`head -c4 $fetched_file | tail -c3`" != "ELF" ]; then
		continue
	fi

	base_name=`basename $fetched_file`

	# Since the directory layout is different between compilation artifact and tarball
	# We find the correct binary in compilation artifact by using find command
	# For kernel, we search sys/GENERIC directly.
	# For world and lib32, we get the topmost relative directory (e.g. usr.bin, bin) the file in
	# to prevent collision of filename
	if [ $tarball_class = "kernel" ]; then
		obj_file=`find "$obj_diff_dir" -type f -name $base_name`
	else
		suffix=${fetched_file##$fetched_diff_dir}
		topmost_path=`echo "$suffix" | cut -d '/' -f1`

		# convert usr/bin to usr.bin
		if [ "$topmost_path" = "usr" ]; then
			second_dir=`echo "$suffix" | cut -d '/' -f2`
			if [ "$second_dir" = "bin"] || [ "$second_dir" = "sbin" ]; then
				topmost_path="${topmost_path}.${second_dir}"
			fi
		fi

		# Ignore the release directory which is used for make image
		if [ ! -d "$obj_diff_dir$topmost_path"  ]; then
		  obj_file=`find "$obj_diff_dir" -path '*/release/*' -prune -o -type f -name $base_name -print`
		else
		  obj_file=`find "$obj_diff_dir$topmost_path" -path '*/release/*' -prune -o -type f -name $base_name -print`
		fi
	fi

	if [ "$obj_file" = "" ]; then
		continue
	fi

	echo "Comparing $obj_file and $fetched_file"
 	ctfdiff $obj_file $fetched_file
done

rm -rf $tarball_dir
