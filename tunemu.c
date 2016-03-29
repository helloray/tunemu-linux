/*
 *  tunemu - Tun device emulation for Linux
 *
 *  Copyright (c) 2009-2013 Friedrich Sch?ller <hans@schoeller.se>
 *  Copyright (c) 2015-2016 Chris Han <helloray@126.com>
 *  All rights reserved.
 *
 *  Redistribution and use in source and binary forms, with or without
 *  modification, are permitted provided that the following conditions are met:
 *  1. Redistributions of source code must retain the above copyright
 *     notice, this list of conditions and the following disclaimer.
 *  2. Redistributions in binary form must reproduce the above copyright
 *     notice, this list of conditions and the following disclaimer in the
 *     documentation and/or other materials provided with the distribution.
 *
 *  THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS "AS IS"
 *  AND ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE
 *  IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE
 *  ARE DISCLAIMED. IN NO EVENT SHALL THE COPYRIGHT HOLDER OR CONTRIBUTORS BE
 *  LIABLE FOR ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR
 *  CONSEQUENTIAL DAMAGES (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF
 *  SUBSTITUTE GOODS OR SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS
 *  INTERRUPTION) HOWEVER CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN
 *  CONTRACT, STRICT LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE)
 *  ARISING IN ANY WAY OUT OF THE USE OF THIS SOFTWARE, EVEN IF ADVISED OF THE
 *  POSSIBILITY OF SUCH DAMAGE.
 *
 */

#include "tunemu.h"

#include <sys/ioctl.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <sys/time.h>
#include <sys/errno.h>
#include <sys/file.h>
#include <sys/stat.h>
#include <sys/utsname.h>
#include <sys/sysmacros.h>

#include <stdio.h>
#include <stdlib.h>
#include <syslog.h>
#include <string.h>
#include <time.h>
#include <memory.h>
#include <utmp.h>
#include <mntent.h>
#include <signal.h>
#include <fcntl.h>
#include <ctype.h>
#include <termios.h>
#include <unistd.h>
#include <pcap.h>
#include <stdarg.h>

#if __GLIBC__ >= 2
#include <asm/types.h>		/* glibc 2 conflicts with linux/types.h */
#include <net/if.h>
#include <net/if_arp.h>
#include <net/route.h>
#include <netinet/if_ether.h>
#else
#include <linux/types.h>
#include <linux/if.h>
#include <linux/if_arp.h>
#include <linux/route.h>
#include <linux/if_ether.h>
#endif
#include <netinet/in.h>
#include <arpa/inet.h>

#ifndef aligned_u64
/* should be defined in sys/types.h */
#define aligned_u64 unsigned long long __attribute__((aligned(8)))
#endif

#include <linux/ppp_defs.h>
#include <linux/if_ppp.h>

#define ERROR_BUFFER_SIZE 1024

char tunemu_error[ERROR_BUFFER_SIZE];

static int pcap_use_count = 0;
static pcap_t *pcap = NULL;

static int data_buffer_length = 0;
static char *data_buffer = NULL;

static void tun_error(char *format, ...)
{
    va_list vl;
    va_start(vl, format);
    vsnprintf(tunemu_error, ERROR_BUFFER_SIZE, format, vl);
    va_end(vl);
}

static void tun_noerror(void)
{
    *tunemu_error = 0;
}

static void closeall(void)
{
    int fd = getdtablesize();
    while (fd--)
        close(fd);

    open("/dev/null", O_RDWR, 0);
    dup(0);
    dup(0);
}

static int ppp_new_instance(void)
{
    int x,flags;
    int ppp_dev_fd=open("/dev/ppp", O_RDWR);
    if(ppp_dev_fd<0)
        return -1;

    tun_noerror();
    return ppp_dev_fd;
}

static int ppp_new_unit(int *unit_number)
{
    int fd = ppp_new_instance();
    if (fd < 0)
        return -1;

    // create ppp unit
    if (ioctl(fd, PPPIOCNEWUNIT, unit_number) < 0)
    {
        tun_error("creating ppp unit: %s", strerror(errno));
        close(fd);
        return -1;
    }

    tun_noerror();
    return fd;
}

static int ppp_setup_unit(int unit_fd)
{
    // send traffic to program
    int flags = SC_LOOP_TRAFFIC;
    if (ioctl(unit_fd, PPPIOCSFLAGS, &flags) < 0)
    {
        tun_error("setting ppp loopback mode: %s", strerror(errno));
        return -1;
    }

    // allow packets
    struct npioctl npi;
    npi.protocol = PPP_IP;
    npi.mode = NPMODE_PASS;
    if (ioctl(unit_fd, PPPIOCSNPMODE, &npi) < 0)
    {
        tun_error("starting ppp unit: %s", strerror(errno));
        return -1;
    }

    tun_noerror();
    return 0;
}

static int open_pcap(void)
{
    if (pcap != NULL)
    {
        pcap_use_count++;
        return 0;
    }

    char errbuf[PCAP_ERRBUF_SIZE];
    pcap = pcap_open_live("lo", BUFSIZ, 0, 1, errbuf);
    pcap_use_count = 1;

    if (pcap == NULL)
    {
        tun_error("opening pcap: %s", errbuf);
        return -1;
    }

    tun_noerror();
    return 0;
}

static void close_pcap(void)
{
    if (pcap == NULL)
        return;

    pcap_use_count--;
    if (pcap_use_count == 0)
    {
        pcap_close(pcap);
        pcap = NULL;
    }
}

static void allocate_data_buffer(int size)
{
    if (data_buffer_length < size)
    {
        free(data_buffer);
        data_buffer_length = size;
        data_buffer = malloc(data_buffer_length);
    }
}

static void make_device_name(tunemu_device device, int unit_number)
{
    snprintf(device, sizeof(tunemu_device), "ppp%d", unit_number);
}

static int check_device_name(tunemu_device device)
{
    if (strlen(device) < 4)
        return -1;

    int unit_number = atoi(device + 3);
    if (unit_number < 0 || unit_number > 999)
        return -1;

    tunemu_device compare;
    make_device_name(compare, unit_number);

    if (strcmp(device, compare) != 0)
        return -1;

    return 0;
}

int tunemu_open(tunemu_device device)
{
    int ppp_unit_number = -1;
    if (device[0] != 0)
    {
        if (check_device_name(device) < 0)
        {
            tun_error("invalid device name \"%s\"", device);
            return -1;
        }

        ppp_unit_number = atoi(device + 3);
    }

    int ppp_unit_fd = ppp_new_unit(&ppp_unit_number);
    if (ppp_unit_fd < 0)
        return -1;

    if (ppp_setup_unit(ppp_unit_fd) < 0)
    {
        close(ppp_unit_fd);
        return -1;
    }

    if (open_pcap() < 0)
    {
        close(ppp_unit_fd);
        return -1;
    }

    make_device_name(device, ppp_unit_number);

    return ppp_unit_fd;
}

int tunemu_close(int ppp_sockfd)
{
    int ret = close(ppp_sockfd);

    if (ret == 0)
        close_pcap();

    return ret;
}

int tunemu_read(int ppp_sockfd, char *buffer, int length)
{
    allocate_data_buffer(length + 2);

    length = read(ppp_sockfd, data_buffer, length + 2);
    if (length < 0)
    {
        tun_error("reading packet: %s", strerror(errno));
        return length;
    }
    tun_noerror();

    length -= 2;
    if (length < 0)
        return 0;

    memcpy(buffer, data_buffer + 2, length);

    return length;
}

int tunemu_write(int ppp_sockfd, char *buffer, int length)
{
    allocate_data_buffer(length + 14);
    memset(data_buffer, 0, 14);
    data_buffer[12] = 0x08;
    memcpy(data_buffer + 14, buffer, length);
    if (pcap == NULL)
    {
        tun_error("pcap not open");
        return -1;
    }
    length = pcap_inject(pcap, data_buffer, length + 14);
    if (length < 0)
    {
        tun_error("injecting packet: %s", pcap_geterr(pcap));
        return length;
    }
    tun_noerror();

    length -= 14;
    if (length < 0)
        return 0;
    return length;
}
