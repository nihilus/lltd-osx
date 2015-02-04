/*
 * Copyright (c) 2000-2012 Apple Inc. All rights reserved.
 *
 * @APPLE_LICENSE_HEADER_START@
 * 
 * This file contains Original Code and/or Modifications of Original Code
 * as defined in and that are subject to the Apple Public Source License
 * Version 2.0 (the 'License'). You may not use this file except in
 * compliance with the License. Please obtain a copy of the License at
 * http://www.opensource.apple.com/apsl/ and read it before using this
 * file.
 * 
 * The Original Code and all software distributed under the License are
 * distributed on an 'AS IS' basis, WITHOUT WARRANTY OF ANY KIND, EITHER
 * EXPRESS OR IMPLIED, AND APPLE HEREBY DISCLAIMS ALL SUCH WARRANTIES,
 * INCLUDING WITHOUT LIMITATION, ANY WARRANTIES OF MERCHANTABILITY,
 * FITNESS FOR A PARTICULAR PURPOSE, QUIET ENJOYMENT OR NON-INFRINGEMENT.
 * Please see the License for the specific language governing rights and
 * limitations under the License.
 * 
 * @APPLE_LICENSE_HEADER_END@
 */

#include <stdlib.h>
#include <unistd.h>
#include <stdio.h>
#include <sys/types.h>
#include <sys/time.h>
#include <sys/ioctl.h>
#include <sys/stat.h>
#include <fcntl.h>
#include <string.h>
#include <sys/socket.h>
#include <errno.h>
#include <net/if.h>
#include <stdbool.h>

#include "bpflib.h"

#define BPF_FORMAT	"/dev/bpf%d"

/*
 bpf_set_timeout - Sets the read timeout parameter. The timeval specifies the length
 of time to wait before timing out a read request. This paramter is init'd to 0 by 
 open(2) indicating no timeout
 */
int
bpf_set_timeout(int fd, struct timeval * tv_p)
{
    return (ioctl(fd, BIOCSRTIMEOUT, tv_p));
}

/*
 bpf_get_data_link - Returns the type of the data link layer underlying the attached 
 interface.  EINVAL is returned if no inter-face has been specified.  The device types, 
 prefixed with ``DLT_'', are defined in <net/bpf.h>.
 
 */
int
bpf_get_data_link(int fd, u_int * dl_p)
{
    return (ioctl(fd, BIOCGDLT, dl_p));
}

/*
 bpf_get_blen - returns the required buffer length for reads on bpf files
 */
int 
bpf_get_blen(int fd, int * blen)
{
    return(ioctl(fd, BIOCGBLEN, blen));
}

/*
 bpf_set_promiscuous - Forces the interface into promiscuous mode.  All packets,
 not just those destined for the local host, are processed. Since more than one file 
 can be listening on a given interface, a listener that opened its interface non-
 promiscuously may receive packets promiscuously.  This problem can be remedied with 
 an appropriate filter.
 */
int
bpf_set_promiscuous(int bpf_fd, int offon) /* NB: int offon = 1 will disable and int offon = 0 will enable. */
{
    return(ioctl(bpf_fd, BIOCPROMISC, &offon));    
} 

/*
 bpf_get_stats - (struct bpf_stat) Returns the following structure of
 packet statistics:
 
 struct bpf_stat {
	 u_int bs_recv;     // number of packets received
	 u_int bs_drop;     // number of packets dropped 
 };
 
 The fields are:
 
 bs_recv the number of packets received by the
 descriptor since opened or reset (including
								   any buffered since the last read call); and
 
 bs_drop the number of packets which were accepted by
 the filter but dropped by the kernel because
 of buffer overflows (i.e., the application's
					  reads aren't keeping up with the packet
					  traffic).
 */
int
bpf_get_stats(int bpf_fd, struct bpf_stat *bs_p)
{
    return ioctl(bpf_fd, BIOCGSTATS, bs_p);  
} 

int
bpf_dispose(int bpf_fd)
{
    if (bpf_fd >= 0)
	return (close(bpf_fd));
    return (0);
}

int
bpf_new()
{
    char bpfdev[256];
    int i;
    int fd = -1;

    for (i = 0; true; i++) {
	snprintf(bpfdev, sizeof(bpfdev), BPF_FORMAT, i);
	fd = open(bpfdev, O_RDWR , 0);
	if (fd >= 0) {
#ifdef SO_TC_CTL
	    int tc = SO_TC_CTL;
	    (void) ioctl(fd, BIOCSETTC, &tc);
#endif /* SO_TC_CTL */
	    break;
	}
	if (errno != EBUSY) {
	    break;
	}
    }
    return (fd);
}

/*
 bpf_setif - Sets the hardware interface associated with the file descriptor. this call
 must be made before any packets can be read. the device name is indicated by setting the
 ifr_name field of the ifreq. Also performs the actions of BIOCFLUSH
 */
int
bpf_setif(int fd, const char * en_name)
{
    struct ifreq ifr;

    strlcpy(ifr.ifr_name, en_name, sizeof(ifr.ifr_name));
    return (ioctl(fd, BIOCSETIF, &ifr));
}

/*
 bpf_set_immediate - enable or disable immediate mode based on the truth value of argument
 value 0 - disable, not 0 - enable.
 When immediate mode is enabled, reads return immediately upon packet reception. Otherwise
 a read will block until either the kernel buffer becomes full or a timeout occurs. Default
 setting is off.
 */
int
bpf_set_immediate(int fd, u_int value)
{
    return (ioctl(fd, BIOCIMMEDIATE, &value));
}

int
bpf_filter_receive_none(int fd)
{
    struct bpf_insn insns[] = {
	BPF_STMT(BPF_RET+BPF_K, 0),
    };
    struct bpf_program prog;

    prog.bf_len = sizeof(insns) / sizeof(struct bpf_insn);
    prog.bf_insns = insns;
    return ioctl(fd, BIOCSETF, &prog);
}

int
bpf_arp_filter(int fd, int type_offset, int type, int pkt_size)
{
    struct bpf_insn insns[] = {
	BPF_STMT(BPF_LD+BPF_H+BPF_ABS, type_offset),
	BPF_JUMP(BPF_JMP+BPF_JEQ+BPF_K, type, 0, 1),
	BPF_STMT(BPF_RET+BPF_K, pkt_size),
	BPF_STMT(BPF_RET+BPF_K, 0),
    };
    struct bpf_program prog;

    prog.bf_len = sizeof(insns) / sizeof(struct bpf_insn);
    prog.bf_insns = insns;
    return ioctl(fd, BIOCSETF, &prog);
}

int bpf_see_sent(int fd, int value) {
  return(ioctl(fd, BIOCSSEESENT, &value));
}

int
bpf_write(int fd, void * pkt, int len)
{
    return (write(fd, pkt, len));
}