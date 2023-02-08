/*
 * FBVNC: a small Linux framebuffer VNC viewer
 *
 * Copyright (C) 2009-2021 Ali Gholami Rudi
 * Copyright (C) 2023 Uwe Klatt
 *
 * Permission to use, copy, modify, and/or distribute this software for any
 * purpose with or without fee is hereby granted, provided that the above
 * copyright notice and this permission notice appear in all copies.
 *
 * THE SOFTWARE IS PROVIDED "AS IS" AND THE AUTHOR DISCLAIMS ALL WARRANTIES
 * WITH REGARD TO THIS SOFTWARE INCLUDING ALL IMPLIED WARRANTIES OF
 * MERCHANTABILITY AND FITNESS. IN NO EVENT SHALL THE AUTHOR BE LIABLE FOR
 * ANY SPECIAL, DIRECT, INDIRECT, OR CONSEQUENTIAL DAMAGES OR ANY DAMAGES
 * WHATSOEVER RESULTING FROM LOSS OF USE, DATA OR PROFITS, WHETHER IN AN
 * ACTION OF CONTRACT, NEGLIGENCE OR OTHER TORTIOUS ACTION, ARISING OUT OF
 * OR IN CONNECTION WITH THE USE OR PERFORMANCE OF THIS SOFTWARE.
 */
#include <errno.h>
#include <fcntl.h>
#include <netdb.h>
#include <netinet/in.h>
#include <poll.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <linux/input.h>
#include <zlib.h>
#include "draw.h"
#include "vnc.h"
#include "d3des.h"

#define MIN(a, b)	((a) < (b) ? (a) : (b))
#define MAX(a, b)	((a) > (b) ? (a) : (b))

#define VNC_PORT	"5900"
#define MAXRES		(1 << 16)
#define CHALLENGESIZE 16

static int cols, rows;		/* framebuffer dimensions */
static int bpp;			/* bytes per pixel */
static int srv_cols, srv_rows;	/* server screen dimensions */
static int or, oc;		/* visible screen offset */
static int mr, mc;		/* mouse position */
static long vnc_nr;		/* number of bytes received */
static long vnc_nw;		/* number of bytes sent */

static char buf[MAXRES];
static char passwd[80];

static z_stream zstr;
static char *z_out;
static int z_outlen;
static int z_outsize;
static int z_outpos;

static int vread(int fd, void *buf, long len)
{
	long nr = 0;
	long n;
	while (nr < len && (n = read(fd, buf + nr, len - nr)) > 0)
		nr += n;
	vnc_nr += nr;
	if (nr < len)
		printf("fbvnc: partial vnc read!\n");
	return nr < len ? -1 : len;
}

static int vwrite(int fd, void *buf, long len)
{
	int nw = write(fd, buf, len);
	if (nw != len)
		printf("fbvnc: partial vnc write!\n");
	vnc_nw += len;
	return nw < len ? -1 : nw;
}

static int z_init(void)
{
	zstr.zalloc = Z_NULL;
	zstr.zfree = Z_NULL;
	zstr.opaque = Z_NULL;
	zstr.avail_in = 0;
	zstr.next_in = Z_NULL;
	if (inflateInit(&zstr) != Z_OK) {
		fprintf(stderr, "fbvnc: failed to initialize a zlib stream\n");
		return 1;
	}
	return 0;
}

static int z_push(void *src, int len)
{
	z_outlen = 0;
	z_outpos = 0;
	zstr.next_in = src;
	zstr.avail_in = len;
	while (zstr.avail_in > 0) {
		int nr;
		zstr.avail_out = sizeof(buf);
		zstr.next_out = (void *) buf;
		if (inflate(&zstr, Z_NO_FLUSH) != Z_OK)
			return 1;
		nr = sizeof(buf) - zstr.avail_out;
		if (z_outlen + nr > z_outsize) {
			char *old = z_out;
			while (z_outlen + nr > z_outsize)
				z_outsize = MAX(z_outsize, 4096) * 2;
			z_out = malloc(z_outsize);
			if (z_outlen)
				memcpy(z_out, old, z_outlen);
			free(old);
		}
		memcpy(z_out + z_outlen, buf, nr);
		z_outlen += nr;
	}
	return 0;
}

static int z_read(void *dst, int len)
{
	if (z_outpos + len > z_outlen)
		return 1;
	memcpy(dst, z_out + z_outpos, len);
	z_outpos += len;
	return 0;
}

static int z_free(void)
{
	inflateEnd(&zstr);
	free(z_out);
	return 0;
}

void rfbEncryptBytes(unsigned char *bytes, char *passwd)
{
	unsigned char key[8];
	unsigned int i;

	for (i = 0; i < 8; i++) {
		if (i < strlen(passwd)) 
			key[i] = passwd[i];
		else 
			key[i] = 0;
	}
	deskey(key, EN0);
	for (i = 0; i < CHALLENGESIZE; i += 8) 
		des(bytes+i, bytes+i);
}

int vnc_auth(int client)
{
	unsigned char challenge[16];
	unsigned long sectype = 0, authResult = 0;

	vread(client, (char *)&sectype, 4);
	sectype = ntohl(sectype);

	if(sectype == VNC_CONN_NOAUTH ) // without authentication
		return 0;
	if(sectype != VNC_CONN_AUTH )   // VNC authentication
		return 1;

	vread(client, (char *)challenge, CHALLENGESIZE);
	if (strlen(passwd) > 8) 
		passwd[8] = '\0';

	rfbEncryptBytes(challenge, passwd);
	
	vwrite(client, (char *)challenge, CHALLENGESIZE);
	vread(client, (char *)&authResult, 4);
	authResult = ntohl(authResult);
	return authResult;
}

static int vnc_connect(char *addr, char *port)
{
	struct addrinfo hints, *addrinfo;
	int fd;

	memset(&hints, 0, sizeof(hints));
	hints.ai_family = AF_UNSPEC;
	hints.ai_socktype = SOCK_STREAM;
	hints.ai_flags = AI_PASSIVE;

	if (getaddrinfo(addr, port, &hints, &addrinfo))
		return -1;
	fd = socket(addrinfo->ai_family, addrinfo->ai_socktype,
			addrinfo->ai_protocol);

	if (connect(fd, addrinfo->ai_addr, addrinfo->ai_addrlen) == -1) {
		close(fd);
		freeaddrinfo(addrinfo);
		return -1;
	}
	freeaddrinfo(addrinfo);
	return fd;
}

static void fbmode_bits(int *rr, int *rg, int *rb)
{
	int mode = FBM_CLR(fb_mode());
	*rr = (mode >> 8) & 0xf;
	*rg = (mode >> 4) & 0xf;
	*rb = (mode >> 0) & 0xf;
}

static int vnc_init(int fd)
{
	char vncver[16];
	int rr, rg, rb;
	struct vnc_clientinit clientinit;
	struct vnc_serverinit serverinit;
	struct vnc_setpixelformat pixfmt_cmd;
	struct vnc_setencoding enc_cmd;
	u32 enc[] = {htonl(VNC_ENC_ZLIB), htonl(VNC_ENC_RRE), htonl(VNC_ENC_RAW)};

	/* handshake */
	if (vread(fd, vncver, 12) < 0)
		return -1;
	strcpy(vncver, "RFB 003.003\n");
	vwrite(fd, vncver, 12);
	if(vnc_auth(fd) != 0)
		return -1;
	
	clientinit.shared = 1;
	vwrite(fd, &clientinit, sizeof(clientinit));
	if (vread(fd, &serverinit, sizeof(serverinit)) < 0)
		return -1;
	if (vread(fd, buf, ntohl(serverinit.len)) < 0)
		return -1;
	srv_cols = ntohs(serverinit.w);
	srv_rows = ntohs(serverinit.h);

	/* set up the framebuffer */
	if (fb_init(getenv("FBDEV")))
		return -1;
	cols = MIN(srv_cols, fb_cols());
	rows = MIN(srv_rows, fb_rows());
	bpp = FBM_BPP(fb_mode());
	mr = rows / 2;
	mc = cols / 2;

	/* send framebuffer configuration */
	pixfmt_cmd.type = VNC_SETPIXELFORMAT;
	pixfmt_cmd.format.bpp = bpp << 3;
	pixfmt_cmd.format.depth = bpp << 3;
	pixfmt_cmd.format.bigendian = 0;
	pixfmt_cmd.format.truecolor = 1;
	fbmode_bits(&rr, &rg, &rb);
	pixfmt_cmd.format.rmax = htons((1 << rr) - 1);
	pixfmt_cmd.format.gmax = htons((1 << rg) - 1);
	pixfmt_cmd.format.bmax = htons((1 << rb) - 1);

	/* assuming colors packed as RGB; shall handle other cases later */
	pixfmt_cmd.format.rshl = rg + rb;
	pixfmt_cmd.format.gshl = rb;
	pixfmt_cmd.format.bshl = 0;
	vwrite(fd, &pixfmt_cmd, sizeof(pixfmt_cmd));

	/* send pixel format */
	enc_cmd.type = VNC_SETENCODING;
	enc_cmd.pad = 0;
	enc_cmd.n = htons(3);
	vwrite(fd, &enc_cmd, sizeof(enc_cmd));
	vwrite(fd, enc, ntohs(enc_cmd.n) * sizeof(enc[0]));

	/* initialize zlib */
	z_init();
	return 0;
}

static int vnc_free(void)
{
	z_free();
	fb_free();
	return 0;
}

static int vnc_refresh(int fd, int inc)
{
	struct vnc_updaterequest fbup_req;
	fbup_req.type = VNC_UPDATEREQUEST;
	fbup_req.inc = inc;
	fbup_req.x = htons(oc);
	fbup_req.y = htons(or);
	fbup_req.w = htons(cols);
	fbup_req.h = htons(rows);
	return vwrite(fd, &fbup_req, sizeof(fbup_req)) < 0 ? -1 : 0;
}

static inline void fb_set(int r, int c, void *mem, int len)
{
	memcpy(fb_mem(r) + c * bpp, mem, len * bpp);
}

static inline void drawfb(char *s, int x, int y, int w, int h)
{
	int sc;		/* screen column offset */
	int bc, bw;	/* buffer column offset / row width */
	int i;
	sc = MAX(0, x - oc);
	bc = x > oc ? 0 : oc - x;
	bw = x + w < oc + cols ? w - bc : w - bc - (x + w - oc - cols);
	for (i = y; i < y + h; i++)
		if (i - or >= 0 && i - or < rows && bw > 0)
			fb_set(i - or, sc, s + ((i - y) * w + bc) * bpp, bw);
}

static inline void drawrect(char *pixel, int x, int y, int w, int h)
{
	int i;
	if (x < 0 || x + w > srv_cols || y < 0 || y + h > srv_rows)
		return;
	for (i = 0; i < w; i++)
		memcpy(buf + i * bpp, pixel, bpp);
	for (i = 0; i < h; i++)
		drawfb(buf, x, y + i, w, 1);
}

static inline int readrect(int fd)
{
	struct vnc_rect uprect;
	int x, y, w, h;
	int i;
	if (vread(fd, &uprect, sizeof(uprect)) <  0)
		return -1;
	x = ntohs(uprect.x);
	y = ntohs(uprect.y);
	w = ntohs(uprect.w);
	h = ntohs(uprect.h);
	if (x < 0 || w < 0 || x + w > srv_cols)
		return -1;
	if (y < 0 || h < 0 || y + h > srv_rows)
		return -1;
	if (uprect.enc == htonl(VNC_ENC_RAW)) {
		for (i = 0; i < h; i++) {
			if (vread(fd, buf, w * bpp) < 0)
				return -1;
			drawfb(buf, x, y + i, w, 1);
		}
	}
	else if (uprect.enc == htonl(VNC_ENC_RRE)) {
		char pixel[8];
		u32 n;
		vread(fd, &n, 4);
		vread(fd, pixel, bpp);
		drawrect(pixel, x, y, w, h);

		for (i = 0; i < ntohl(n); i++) {
			u16 pos[4];
			vread(fd, pixel, bpp);
			vread(fd, pos, 8);
			drawrect(pixel, x + ntohs(pos[0]), y + ntohs(pos[1]), ntohs(pos[2]), ntohs(pos[3]));
		}
	}
	else if (uprect.enc == htonl(VNC_ENC_ZLIB)) {
		int zlen;
		char *zdat;
		vread(fd, &zlen, 4);
		zdat = malloc(ntohl(zlen));
		vread(fd, zdat, ntohl(zlen));
		z_push(zdat, ntohl(zlen));
		free(zdat);
		for (i = 0; i < h; i++) {
			z_read(buf, w * bpp);
			drawfb(buf, x, y + i, w, 1);
		}
	}
	return 0;
}

static int vnc_event(int fd)
{
	char msg[1 << 12];
	struct vnc_update *fbup = (void *) msg;
	struct vnc_servercuttext *cuttext = (void *) msg;
	struct vnc_setcolormapentries *colormap = (void *) msg;
	int i;
	int n;

	if (vread(fd, msg, 1) < 0)
		return -1;
	switch (msg[0]) {
		case VNC_UPDATE:
			vread(fd, msg + 1, sizeof(*fbup) - 1);
			n = ntohs(fbup->n);
			for (i = 0; i < n; i++)
				if (readrect(fd))
					return -1;
			break;
		case VNC_BELL:
			break;
		case VNC_SERVERCUTTEXT:
			vread(fd, msg + 1, sizeof(*cuttext) - 1);
			vread(fd, buf, ntohl(cuttext->len));
			break;
		case VNC_SETCOLORMAPENTRIES:
			vread(fd, msg + 1, sizeof(*colormap) - 1);
			vread(fd, buf, ntohs(colormap->n) * 3 * 2);
			break;
		default:
			fprintf(stderr, "fbvnc: unknown vnc msg %d\n", msg[0]);
			return -1;
	}
	return 0;
}

static unsigned long GetTicks(void)
{
  struct timeval tv;
  gettimeofday(&tv,NULL);
  return  tv.tv_sec*1000 + tv.tv_usec/1000;
}

static int rat_event(int fd, int ratfd)
{
	int i, n;
	static struct vnc_pointerevent me = {VNC_POINTEREVENT};
	struct input_event events[64];
	static unsigned long ticks;

	n = read(ratfd , events, sizeof( struct input_event ) * 64 );
	if (n < (int)sizeof(struct input_event))
		return 0;

	for ( i = 0; i < (n / (int)sizeof(struct input_event)); i++ ) {
		unsigned int type;
		unsigned int code;
		long         value;

		type  = events[ i ].type;
		code  = events[ i ].code;
		value = events[ i ].value;
		if ( type == EV_ABS ) {
			if ( code == ABS_Y  || code == ABS_MT_POSITION_Y )
				me.y = htons(value);
			else if ( code == ABS_X || code == ABS_MT_POSITION_X )
				me.x = htons(value);
		}
		else if ( type == EV_KEY && code == BTN_TOUCH ) {
			if ( value )
				me.mask |= VNC_BUTTON1_MASK;
			else
				me.mask &= !VNC_BUTTON1_MASK;
		}
		else if(type == EV_SYN ) {
			if(GetTicks() > ticks+100) {
				ticks = GetTicks();
				vwrite(fd, &me, sizeof(me));
			}
		}
	}
	vwrite(fd, &me, sizeof(me));
	if (vnc_refresh(fd, 0))
		return -1;
	return 0;
}

static void mainloop(int vnc_fd, int rat_fd)
{
	struct pollfd ufds[2];
	int pending = 0;
	int err;
	ufds[0].fd = vnc_fd;
	ufds[0].events = POLLIN;
	ufds[1].fd = rat_fd;
	ufds[1].events = POLLIN;
	rat_event(vnc_fd, -1);
	if (vnc_refresh(vnc_fd, 0))
		return;
	while (1) {
		err = poll(ufds, 2, 500);
		if (err == -1 && errno != EINTR)
			break;
		if (!err)
			continue;
		if (ufds[0].revents & POLLIN) {
			if (vnc_event(vnc_fd) == -1)
				break;
			pending = 0;
		}
		if (ufds[1].revents & POLLIN)
			if (rat_event(vnc_fd, rat_fd) == -1)
				break;
		if (!pending++)
			if (vnc_refresh(vnc_fd, 1))
				break;
	}
}

int main(int argc, char * argv[])
{
	char port[12] = VNC_PORT;
	char host[80];
	int opt;
	int vnc_fd, rat_fd;
	
	if(argc == 1) {
		fprintf(stderr, "Usage: %s [-p password] [-t port] host\n", argv[0]);
		return 0;
	}
	while ((opt = getopt(argc, argv, "t:p:")) != -1) {
		switch (opt) {
		case 't': strncpy(port, optarg, sizeof(port)-1); break;
		case 'p': strncpy(passwd, optarg, sizeof(passwd)-1); break;
		}
	}
	strncpy(host, argv[optind], sizeof(host)-1);

	if ((vnc_fd = vnc_connect(host, port)) < 0) {
		fprintf(stderr, "fbvnc: could not connect to %s:%s\n", host, port);
		return 1;
	}
	if (vnc_init(vnc_fd) < 0) {
		close(vnc_fd);
		fprintf(stderr, "fbvnc: vnc init failed!\n");
		return 1;
	}
	/* touch device */
	rat_fd = open("/dev/input/event0", O_RDONLY);

	mainloop(vnc_fd, rat_fd);

	vnc_free();
	close(vnc_fd);
	close(rat_fd);
	return 0;
}
