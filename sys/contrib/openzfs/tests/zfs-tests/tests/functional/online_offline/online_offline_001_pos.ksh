#!/bin/ksh -p
# SPDX-License-Identifier: CDDL-1.0
#
# CDDL HEADER START
#
# The contents of this file are subject to the terms of the
# Common Development and Distribution License (the "License").
# You may not use this file except in compliance with the License.
#
# You can obtain a copy of the license at usr/src/OPENSOLARIS.LICENSE
# or https://opensource.org/licenses/CDDL-1.0.
# See the License for the specific language governing permissions
# and limitations under the License.
#
# When distributing Covered Code, include this CDDL HEADER in each
# file and include the License file at usr/src/OPENSOLARIS.LICENSE.
# If applicable, add the following below this CDDL HEADER, with the
# fields enclosed by brackets "[]" replaced with your own identifying
# information: Portions Copyright [yyyy] [name of copyright owner]
#
# CDDL HEADER END
#

#
# Copyright 2009 Sun Microsystems, Inc.  All rights reserved.
# Use is subject to license terms.
#

#
# Copyright (c) 2013, 2016 by Delphix. All rights reserved.
#

. $STF_SUITE/include/libtest.shlib
. $STF_SUITE/tests/functional/online_offline/online_offline.cfg

#
# DESCRIPTION:
# Turning a disk offline and back online during I/O completes.
#
# STRATEGY:
# 1. Create a mirror and start some random I/O
# 2. For each disk in the mirror, set it offline and online
# 3. Verify the integrity of the file system and the resilvering.
#

verify_runnable "global"
log_onexit cleanup

DISKLIST=$(get_disklist $TESTPOOL)

function cleanup
{
	kill $killpid >/dev/null 2>&1

	#
	# Ensure we don't leave disks in the offline state
	#
	for disk in $DISKLIST; do
		log_must zpool online $TESTPOOL $disk
		log_must check_state $TESTPOOL $disk "online"
	done
	sleep 1 # Delay for resilver to start
	log_must zpool wait -t resilver $TESTPOOL

	[[ -e $TESTDIR ]] && log_must rm -rf $TESTDIR/*
}

log_assert "Turning a disk offline and back online during I/O completes."

file_trunc -f $((64 * 1024 * 1024)) -b 8192 -c 0 -r $TESTDIR/$TESTFILE1 &
typeset killpid="$! "

for disk in $DISKLIST; do
	for i in 'do_offline' 'do_offline_while_already_offline'; do
		log_must zpool offline $TESTPOOL $disk
		log_must check_state $TESTPOOL $disk "offline"
	done

	log_must zpool online $TESTPOOL $disk
	log_must check_state $TESTPOOL $disk "online"
	sleep 1 # Delay for resilver to start
	log_must zpool wait -t resilver $TESTPOOL
done

log_must kill $killpid
sync_all_pools
log_must sync

typeset dir=$(get_device_dir $DISKS)
verify_filesys "$TESTPOOL" "$TESTPOOL/$TESTFS" "$dir"

log_pass
