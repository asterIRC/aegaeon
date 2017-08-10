# -*- syntax: tcl -*-
package require critcl
package provide aegaeon 0.01.0.1

if {![critcl::compiling]} {exit}

if {0} {
/*
 * Copyright (c) 2017 the management of umbrellix.net
 *
 * Permission is hereby granted, free of charge, to any person
 * obtaining a copy of this software and associated documentation files
 * (the "Software"), to deal in the Software without restriction,
 * including without limitation the rights to use, copy, modify, merge,
 * publish, distribute, sublicense, and/or sell copies of the Software,
 * and to permit persons to whom the Software is furnished to do so,
 * subject to the following conditions:
 * 
 *  The above copyright notice and this permission notice shall be included
 *  in all copies or substantial portions of the Software.
 * 
 * THE SOFTWARE IS PROVIDED "AS
 * IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR IMPLIED, INCLUDING BUT
 * NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY, FITNESS FOR A
 * PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
 * AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR
 * OTHER LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR
 * OTHERWISE, ARISING FROM, OUT OF OR IN CONNECTION WITH THE SOFTWARE
 * OR THE USE OR OTHER DEALINGS IN THE SOFTWARE.
 */
}

critcl::ccode {
#include <sys/types.h>
#include <sys/socket.h>
#include <fcntl.h>
#include <sys/errno.h>
#include <netinet/in.h>
#include <mowgli.h>
#include <uthash.h>
#include <netdb.h>

int sslctx_appdata;

typedef struct {
	int fd;
	mowgli_vio_t *vio;
	UT_hash_handle hh;
} aegaeon_t;

typedef struct {
	Tcl_Interp *interp;
	char* read; // Also for the accept callback for [aegaeon vio-server]
	char* write;
	char* error;
	void *privdata;
} aegaeon_userdata;

#include <aegaeon.c>
mowgli_vio_evops_t aegaeon_evops = {
	.read_cb = aegaeon_react;
	.write_cb = aegaeon_react;
};

mowgli_eventloop_t *aegaeon_wait;
}
critcl::buildrequirement {
	package require critcl::emap
}

critcl::emap protofamily {
PF_LOCAL PF_LOCAL
PF_UNIX PF_UNIX
PF_INET PF_INET
PF_INET6 PF_INET6
PF_ROUTE PF_ROUTE
PF_LINK PF_LINK
PF_KEY PF_KEY
PF_NATM PF_NATM
PF_NETGRAPH PF_NETGRAPH
PF_IEEE80211 PF_IEEE80211
PF_BLUETOOTH PF_BLUETOOTH
PF_INET_SDP PF_INET_SDP
PF_INET6_SDP PF_INET6_SDP
} -nocase

critcl::emap socktype {
SOCK_STREAM SOCK_STREAM
SOCK_DGRAM SOCK_DGRAM
SOCK_RAW SOCK_RAW
SOCK_RDM SOCK_RDM
SOCK_SEQPACKET SOCK_SEQPACKET
} -nocase

critcl::emap protonum {
IPPROTO_IP IPPROTO_IP
IPPROTO_ICMP IPPROTO_ICMP
IPPROTO_TCP IPPROTO_TCP
IPPROTO_UDP IPPROTO_UDP
IPPROTO_IPV6 IPPROTO_IPV6
IPPROTO_SCTP IPPROTO_SCTP
} -nocase

namespace eval ::aegaeon {

critcl::cproc csocket {protofamily domain socktype type protonum protocol} int {
	return socket(domain, type, protocol);
}


critcl::cproc cconnect {int socket char* hostname char* servname
                       int hint_flags protofamily hint_family domain hint_socktype
                       protonum hint_protocol} int {
	//We have to somehow convert this mess of stuff into a connect() call.
	if (socket == -1) return -16;

	struct addrinfo *hints, *r, *resultnull;
	int error, connerror;

	error = connerror = 0;

	hints = (struct addrinfo *)malloc(sizeof((struct addrinfo)));
	hints->ai_family = hint_family;
	hints->ai_socktype = hint_socktype;
	hints->ai_protocol = hint_protocol;
	error = getaddrinfo(hostname, servname, hints, &resultnull);

	if (error) return (0 - error);

	for (r = resultnull; r != NULL; r = r->ai_next) {
		if (connect(socket, res->ai_addr, res->ai_addrlen) != 0) {
			connerror = errno;
			continue;
		}

		break;
	}

	freeaddrinfo(resultnull);

	if (error || connerror) {
		return 
	}

}

#// cbind returns:
#// int, negative if error, passed socket if success

critcl::cproc cbind {int socket char* hostname char* servname
                     int hint_flags protofamily hint_family domain hint_socktype
                     protonum hint_protocol} int {
	//We have to somehow convert this mess of stuff into a connect() call.
	if (socket == -1) return -16;

	struct addrinfo *hints, *r, *resultnull;
	int error, binderror;

	error = binderror = 0;

	hints = (struct addrinfo *)malloc(sizeof((struct addrinfo)));
	hints->ai_family = hint_family;
	hints->ai_socktype = hint_socktype;
	hints->ai_protocol = hint_protocol;
	error = getaddrinfo(hostname, servname, hints, &resultnull);

	if (error) return (0 - error);

	for (r = resultnull; r != NULL; r = r->ai_next) {
		if (bind(socket, res->ai_addr, res->ai_addrlen) != 0) {
			binderror = errno;
			continue;
		}

		break
	}

	freeaddrinfo(resultnull);

	if (error || binderror) {
		return (0 - (error | (connerror << 8)));
	}	return socket;

}

#// crecv: int fd, char* stopchars, int maxlen
# inputs: file descriptor, maximum length
# if maxlen == 0, maxlen = 16384
# side effects: $name filled with characters up to maxlen, or empty string
# output: 0 = eof, >=1 = read bytes, <0, error (number is |retval|)

critcl::cproc crecv {Tcl_Interp* interp int fd char* stopchars int maxlen
                     object name1 object name2} int {
	// Very slow method
	int continue, i, error, readbytes;
	if (maxlen == 0) maxlen = 16384;
	if (maxlen > 262144) maxlen = 262144; // Clamp to 262kB
	unsigned char *output = Tcl_Alloc(maxlen+1);
	unsigned char obuf[maxlen+1];
	memset(output, 0, maxlen);
	i = 0;

	do {
		switch ((readbytes = recv(fd, &obuf, maxlen, 0))) {
			case 0:
				error = -1;
				break;
			case -1:
				error = errno;
				break;
			default:
				memcpy(output, &obuf, ((strlen(output) +
				readbytes) > maxlen) ?
					(maxlen - (strlen(output) + readbytes)) :
					readbytes);
				break
		}
		if (!continue && !error) {
			break;
		}

		i += readbytes;
	} while(0);

	Tcl_ObjSetVar2(interp, name1, name2, Tcl_NewByteArrayObj(output, i), 0);

	return (error == 0) ? 0 :
			(error == -1) ? 1 :
			0 - error;
}

#// csend: int socket, tcl string stringtosend
# input: fd, string
# output: did it succeed? positive values are yes, negatives are no

critcl::cproc csend {Tcl_Interp* interp int fd object stringtosend} int {
	// Probably a tad faster
	int len, error;
	unsigned char *input = Tcl_GetByteArrayFromObj(stringtosend, &len);

	switch (send(fd, input, len, MSG_NOSIGNAL)) {
		case 0:
			error = -1;
			break;
		case -1:
			error = errno;
			break;
		default:
			error = 0;
			break;
	}

	return (error == 0) ? 0 : 0 - error;
}

# Anyway, what was I saying? Oh yeah, some stuff about Mowgli.
# mowgli_eventloop_create: creates a mowgli event loop.
# inputs: none.
# outputs: the address of whatever funky struct mowgli is doing.

namespace eval ::aegaeon::mowgli {

critcl::cproc eventloop_create {} dstring {
	char *o = Tcl_Alloc(40);
	memset(o, 0, 40);
	mowgli_eventloop_t *el = mowgli_eventloop_create();
	sprintf(o, "0x%lx", el);
	return o;
}

# api difference: no userdata!

critcl::cproc vio_create {Tcl_Interp* interp} dstring {
	char *o = Tcl_Alloc(40);
	memset(o, 0, 40);
	aegaeon_userdata *ud;
	ud = malloc(sizeof(aegaeon_userdata));
	memset(ud, 0, sizeof(aegaeon_userdata));
	ud->interp = interp;
	mowgli_vio_t *el = mowgli_vio_create(ud);
	sprintf(o, "0x%lx", el);
	return o;
}

critcl::cproc vio_tls_socket {char* vptrs protofamily family socktype type protonum proto} int {
#ifndef HAVE_OPENSSL
	return -255;
#endif
	unsigned long vptr = strtoul(vptrs, NULL, 16);
	mowgli_vio_t *vio = (mowgli_vio_t *) vptr;
	aegaeon_ssldata *verify_script = malloc(sizeof(aegaeon_ssldata));
	memset(verify_script, 0, sizeof(aegaeon_ssldata));

	(aegaeon_userdata *)(vio->userdata)->privdata = (void *)verify_script;

	mowgli_vio_openssl_setssl(vio, NULL, NULL);
	if (vio->ops->socket(vio, family, type, proto) != 0) return 1;
	
}

critcl::cproc vio_socket {char* vptrs protofamily family socktype type protonum proto} int {
	unsigned long vptr = strtoul(vptrs, NULL, 16);
	mowgli_vio_t *vio = (mowgli_vio_t *) vptr;
	return vio->ops->socket(vio, family, type, proto);
}

critcl::cproc vio_destroy {char* vptrs} void {
	unsigned long vptr = strtoul(vptrs, NULL, 16);
	mowgli_vio_t *vio = (mowgli_vio_t *) vptr;
	mowgli_vio_destroy(vio);
	return;
}

critcl::cproc vio_connect {char *vptrs char* hostname char* servname
                       int hint_flags protofamily hint_family domain hint_socktype
                       protonum hint_protocol} int {
	//We have to somehow convert this mess of stuff into an ops->connect() call.
	unsigned long vptr = strtoul(vptrs, NULL, 16);
	mowgli_vio_t *vio = (mowgli_vio_t *) vptr;
#ifdef HAVE_OPENSSL
	SSL_CTX *ctx;
#endif

	mowgli_vio_sockaddr_t *vsockaddr;

	struct addrinfo *hints, *r, *resultnull;
	int error, connerror;

	error = connerror = 0;

	hints = (struct addrinfo *)malloc(sizeof((struct addrinfo)));
	hints->ai_family = hint_family;
	hints->ai_socktype = hint_socktype;
	hints->ai_protocol = hint_protocol;
	error = getaddrinfo(hostname, servname, hints, &resultnull);

	if (error) return (0 - error);

	for (r = resultnull; r != NULL; r = r->ai_next) {
		mowgli_vio_sockaddr_from_struct(vsockaddr, res->ai_addr, res->ai_addrlen);

		if (vio->ops->connect(vio, vsockaddr) != 0) {
			connerror = errno;
			continue;
		}

#ifdef HAVE_OPENSSL

		if ((ctx = mowgli_vio_openssl_getsslcontext(vio)) != NULL) {
			// Set to verify peer.
			SSL_CTX_set_ex_data(ctx, sslctx_appdata, (void *)vio);
			SSL_CTX_set_verify(ctx, SSL_VERIFY_PEER, &aegaeon_verify_callback);
		}

#endif

		break;
	}

	freeaddrinfo(resultnull);

	if (error || connerror) {
		return 
	}

}

critcl::cproc vio_recv {Tcl_Interp* interp char *vptrs int maxlen
                     object name1 object name2} int {
	unsigned long vptr = strtoul(vptrs, NULL, 16);
	mowgli_vio_t *vio = (mowgli_vio_t *) vptr;

	int continue, i, error, readbytes;
	if (maxlen == 0) maxlen = 16384;
	if (maxlen > 262144) maxlen = 262144; // Clamp to 262kB
	unsigned char *output = Tcl_Alloc(maxlen+1);
	unsigned char obuf[maxlen+1];
	memset(output, 0, maxlen);
	i = 0;

	do {
		switch ((readbytes = vio->ops->read(vio, &obuf, maxlen))) {
			case 0:
				error = -1;
				break;
			case -1:
				error = errno;
				break;
			default:
				memcpy(output, &obuf, ((strlen(output) +
				readbytes) > maxlen) ?
					(maxlen - (strlen(output) + readbytes)) :
					readbytes);
				break
		}
		if (!continue && !error) {
			break;
		}

		i += readbytes;
	} while(0);

	Tcl_ObjSetVar2(interp, name1, name2, Tcl_NewByteArrayObj(output, i), 0);

	return (error == 0) ? 0 :
			(error == -1) ? 1 :
			0 - error;
}

critcl::cproc vio_send {Tcl_Interp* interp char* vptrs object stringtosend} int {
	unsigned long vptr = strtoul(vptrs, NULL, 16);
	mowgli_vio_t *vio = (mowgli_vio_t *) vptr;

	int len, error;
	unsigned char *input = Tcl_GetByteArrayFromObj(stringtosend, &len);

	switch (vio->ops->write(fd, input, len)) {
		case 0:
			error = -1;
			break;
		case -1:
			error = errno;
			break;
		default:
			error = 0;
			break;
	}

	return (error == 0) ? 0 : 0 - error;
}


namespace export *
namespace ensemble create

}

namespace export *
namespace ensemble create

}

critcl::cproc getnewappdata {} void {
	sslctx_appdata = SSL_CTX_get_new_index();
}

getnewappdata
