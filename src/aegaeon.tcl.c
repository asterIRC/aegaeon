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

critcl::source ../critflags.tcl

critcl::cflags -g -fPIC -DPIC -std=gnu99 -I /usr/home/hadron/src/aegaeon/libmowgli-2/run/include
critcl::ldflags -lssl

critcl::cheaders /usr/home/hadron/src/aegaeon/libmowgli-2/run/include

critcl::ccode {
#include <sys/types.h>
#include <sys/socket.h>
#include <openssl/ssl.h>
#include <openssl/evp.h>
#include <fcntl.h>
#include <sys/errno.h>
#include <netinet/in.h>
#include <libmowgli-2/mowgli.h>
#include <uthash.h>
#include <netdb.h>

int sslctx_appdata = -2;

typedef struct {
	int fd;
	mowgli_vio_t *vio;
	UT_hash_handle hh;
} aegaeon_t;

typedef struct {
	Tcl_Interp *interp;
	Tcl_Obj* read; // Also for the accept callback for [aegaeon vio-server]
	// And for the time callback for secondly timers
	Tcl_Obj* write; // Is the "arg" for the timer callback
	Tcl_Obj* error;
	void *privdata; // For the timer, is an int* 1 if the timer was once
	                // and 0 otherwise
} aegaeon_userdata;

#include <aegaeon.c>
mowgli_vio_evops_t aegaeon_evops = {
	.read_cb = &aegaeon_react,
	.write_cb = &aegaeon_react
};

mowgli_eventloop_t *aegaeon_wait;
}
critcl::buildrequirement {
	package require critcl::enum
}

::critcl::cdefines [list PF_* AF_* IPPROTO_* SOCK_* X509_V_*]

critcl::cproc csocket {int domain int type int protocol} int {
	return socket(domain, type, protocol);
}


critcl::cproc cconnect {int socket char* hostname char* servname
                       int hint_flags int hint_family int hint_socktype
                       int hint_protocol} int {
	//We have to somehow convert this mess of stuff into a connect() call.
	if (socket == -1) return -16;

	struct addrinfo *hints, *r, *resultnull;
	int error, connerror;

	error = connerror = 0;

	hints = (struct addrinfo *)malloc(sizeof(struct addrinfo));
	hints->ai_family = hint_family;
	hints->ai_socktype = hint_socktype;
	hints->ai_protocol = hint_protocol;
	error = getaddrinfo(hostname, servname, hints, &resultnull);

	if (error) return (0 - error);

	for (r = resultnull; r != NULL; r = r->ai_next) {
		if (connect(socket, r->ai_addr, r->ai_addrlen) != 0) {
			connerror = errno;
			continue;
		}

		break;
	}

	freeaddrinfo(resultnull);

	if (error || connerror) {
		return (0 - (error | (connerror << 8)));
	} else return socket;

}

#// cbind returns:
#// int, negative if error, passed socket if success

critcl::cproc cbind {int socket char* hostname char* servname
                     int hint_flags int hint_family int hint_socktype
                     int hint_protocol} int {
	//We have to somehow convert this mess of stuff into a connect() call.
	if (socket == -1) return -16;

	struct addrinfo *hints, *r, *resultnull;
	int error, binderror;

	error = binderror = 0;

	hints = (struct addrinfo *)malloc(sizeof(struct addrinfo));
	hints->ai_family = hint_family;
	hints->ai_socktype = hint_socktype;
	hints->ai_protocol = hint_protocol;
	error = getaddrinfo(hostname, servname, hints, &resultnull);

	if (error) return (0 - error);

	for (r = resultnull; r != NULL; r = r->ai_next) {
		if (bind(socket, r->ai_addr, r->ai_addrlen) != 0) {
			binderror = errno;
			continue;
		}

		break;
	}

	freeaddrinfo(resultnull);

	if (error || binderror) {
		return (0 - (error | (binderror << 8)));
	} else return socket;

}

#// crecv: int fd, char* stopchars, int maxlen
# inputs: file descriptor, maximum length
# if maxlen == 0, maxlen = 16384
# side effects: $name filled with characters up to maxlen, or empty string
# output: 0 = eof, >=1 = read bytes, <0, error (number is |retval|)

critcl::cproc crecv {Tcl_Interp* interp int fd char* stopchars int maxlen
                     object name1 object name2} int {
	// Very slow method
	int i, error, readbytes;
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
				break;
		}
		if (!error) {
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

critcl::cproc eventloop_create {} dstring {
	char *o = Tcl_Alloc(40);
	memset(o, 0, 40);
	mowgli_eventloop_t *el = mowgli_eventloop_create();
	sprintf(o, "0x%lx", el);
	return o;
}

critcl::cproc eventloop_crank {char* elptrs} void {
	unsigned long elptr = strtoul(elptrs, NULL, 16);
	mowgli_eventloop_t *el = (mowgli_eventloop_t *) elptr;

	mowgli_eventloop_run_once(el);
}

critcl::cproc eventloop_fire {char* elptrs} void {
	unsigned long elptr = strtoul(elptrs, NULL, 16);
	mowgli_eventloop_t *el = (mowgli_eventloop_t *) elptr;

	mowgli_eventloop_run(el);
}

critcl::cproc timer_add {Tcl_Interp* interp char* elptrs char* name
                         object script object arg int every} dstring {
	char *o = Tcl_Alloc(40);
	memset(o, 0, 40);

	unsigned long elptr = strtoul(elptrs, NULL, 16);
	mowgli_eventloop_t *el = (mowgli_eventloop_t *) elptr;

	aegaeon_userdata *ud = malloc(sizeof(aegaeon_userdata));
	memset (ud, 0, sizeof(aegaeon_userdata));

	ud->interp = interp;

	ud->read = script;
	Tcl_IncrRefCount(script);

	ud->write = arg;
	Tcl_IncrRefCount(arg);

	ud->privdata = malloc(sizeof(int));
	*(int *)(ud->privdata) = 1;

	mowgli_eventloop_timer_t *elt = mowgli_timer_add(el, name,
	                  &aegaeon_tick, ud, every);
	sprintf(o, "0x%lx", elt);
	return o;
}

critcl::cproc mowgli_after {Tcl_Interp* interp char* elptrs char* name
                         object script object arg int after} void {
	unsigned long elptr = strtoul(elptrs, NULL, 16);
	mowgli_eventloop_t *el = (mowgli_eventloop_t *) elptr;

	aegaeon_userdata *ud = malloc(sizeof(aegaeon_userdata));
	memset (ud, 0, sizeof(aegaeon_userdata));

	ud->interp = interp;

	ud->read = script;
	Tcl_IncrRefCount(script);

	ud->write = arg;
	Tcl_IncrRefCount(arg);

	ud->privdata = malloc(sizeof(int));
	*(int *)(ud->privdata) = 0;

	mowgli_timer_add_once(el, name, &aegaeon_tick, ud, after);
}

# api difference: no userdata!

critcl::cproc vio_create {Tcl_Interp* interp} dstring {
	char *o = Tcl_Alloc(40);
	memset(o, 0, 40);
	aegaeon_userdata *ud;
	ud = malloc(sizeof(aegaeon_userdata));
	memset(ud, 0, sizeof(aegaeon_userdata));
	ud->interp = interp;
	ud->read = NULL;
	ud->write = NULL;
	ud->error = NULL;
	mowgli_vio_t *vio = mowgli_vio_create(ud);
	sprintf(o, "0x%lx", vio);
	return o;
}

critcl::cproc vio_tls_socket {char* vptrs int family int type int proto} int {
#ifndef HAVE_OPENSSL
	return -255;
#endif
	unsigned long vptr = strtoul(vptrs, NULL, 16);
	mowgli_vio_t *vio = (mowgli_vio_t *) vptr;
	aegaeon_ssldata *verify_script = malloc(sizeof(aegaeon_ssldata));
	memset(verify_script, 0, sizeof(aegaeon_ssldata));

	((aegaeon_userdata *)(vio->userdata))->privdata = (void *)verify_script;

	mowgli_vio_openssl_setssl(vio, NULL, NULL);
	if (vio->ops->socket(vio, family, type, proto) != 0) return 1;
	
}

critcl::cproc vio_socket {char* vptrs int family int type int proto} int {
	unsigned long vptr = strtoul(vptrs, NULL, 16);
	mowgli_vio_t *vio = (mowgli_vio_t *) vptr;
	return vio->ops->socket(vio, family, type, proto);
}

# vio_fileevent_readable/writable - only part of the tcl part

critcl::cproc vio_fileevent_readable_set {char* vptrs object cb} void {
	unsigned long vptr = strtoul(vptrs, NULL, 16);
	mowgli_vio_t *vio = (mowgli_vio_t *) vptr;

	((aegaeon_userdata *)(vio->userdata))->read = cb;
	Tcl_IncrRefCount(cb);
};

critcl::cproc vio_fileevent_writable_set {char* vptrs object cb} void {
	unsigned long vptr = strtoul(vptrs, NULL, 16);
	mowgli_vio_t *vio = (mowgli_vio_t *) vptr;

	((aegaeon_userdata *)(vio->userdata))->write = cb;
	Tcl_IncrRefCount(cb);
};

# Probably not used in mowgli, but we have space for it :)

critcl::cproc vio_fileevent_error_set {char* vptrs object cb} void {
	unsigned long vptr = strtoul(vptrs, NULL, 16);
	mowgli_vio_t *vio = (mowgli_vio_t *) vptr;

	((aegaeon_userdata *)(vio->userdata))->error = cb;
	Tcl_IncrRefCount(cb);
};

## unset

critcl::cproc vio_fileevent_readable_unset {char* vptrs} void {
	unsigned long vptr = strtoul(vptrs, NULL, 16);
	mowgli_vio_t *vio = (mowgli_vio_t *) vptr;

	Tcl_DecrRefCount(((aegaeon_userdata *)(vio->userdata))->read);
	((aegaeon_userdata *)(vio->userdata))->read = NULL;
};

critcl::cproc vio_fileevent_writable_unset {char* vptrs} void {
	unsigned long vptr = strtoul(vptrs, NULL, 16);
	mowgli_vio_t *vio = (mowgli_vio_t *) vptr;

	Tcl_DecrRefCount(((aegaeon_userdata *)(vio->userdata))->write);
	((aegaeon_userdata *)(vio->userdata))->write = NULL;
};

# Probably not used in mowgli, but we have space for it :)

critcl::cproc vio_fileevent_error_unset {char* vptrs} void {
	unsigned long vptr = strtoul(vptrs, NULL, 16);
	mowgli_vio_t *vio = (mowgli_vio_t *) vptr;

	Tcl_DecrRefCount(((aegaeon_userdata *)(vio->userdata))->error);
	((aegaeon_userdata *)(vio->userdata))->error = NULL;
};

critcl::cproc vio_eventloop_attach {char* vptrs char* elptrs} void {
	unsigned long vptr = strtoul(vptrs, NULL, 16);
	mowgli_vio_t *vio = (mowgli_vio_t *) vptr;

	unsigned long elptr = strtoul(elptrs, NULL, 16);
	mowgli_eventloop_t *el = (mowgli_eventloop_t *) elptr;

	mowgli_vio_eventloop_attach(vio, el, &aegaeon_evops);
}

critcl::cproc vio_destroy {char* vptrs} void {
	unsigned long vptr = strtoul(vptrs, NULL, 16);
	mowgli_vio_t *vio = (mowgli_vio_t *) vptr;
	mowgli_vio_destroy(vio);
	return;
}

critcl::cproc timer_destroy {char* elptrs char* tptrs} void {
	unsigned long elptr = strtoul(elptrs, NULL, 16);
	mowgli_eventloop_t *el = (mowgli_eventloop_t *) elptr;

	unsigned long tptr = strtoul(tptrs, NULL, 16);
	mowgli_eventloop_timer_t *t = (mowgli_eventloop_timer_t *) tptr;

	mowgli_timer_destroy(el, t);
	return;
}

critcl::cproc vio_eventloop_detach {char* vptrs} void {
	unsigned long vptr = strtoul(vptrs, NULL, 16);
	mowgli_vio_t *vio = (mowgli_vio_t *) vptr;
	mowgli_vio_eventloop_detach(vio);
	return;
}

critcl::cproc vio_connect {char* vptrs char* hostname char* servname
                       int hint_flags int hint_family int hint_socktype
                       int hint_protocol} int {
	//We have to somehow convert this mess of stuff into an ops->connect() call.
	unsigned long vptr = strtoul(vptrs, NULL, 16);
	mowgli_vio_t *vio = (mowgli_vio_t *) vptr;
#ifdef HAVE_OPENSSL
	SSL *sslh;
#endif

	mowgli_vio_sockaddr_t *vsockaddr;

	struct addrinfo hints, *r, *resultnull;
	int error, connerror;

	error = connerror = 0;

	memset(&hints, 0, sizeof(hints));
	hints.ai_family = hint_family;
	hints.ai_socktype = hint_socktype;
	error = getaddrinfo(hostname, servname, &hints, &resultnull);

	if (error) return (0 - error);

	for (r = resultnull; r != NULL; r = r->ai_next) {
		mowgli_vio_sockaddr_from_struct(vsockaddr, r->ai_addr, r->ai_addrlen);

		if ((connerror = vio->ops->connect(vio, vsockaddr)) != 0) {
			continue;
		}

#ifdef HAVE_OPENSSL

		if ((sslh = mowgli_vio_openssl_getsslhandle(vio)) != NULL) {
			if (sslctx_appdata == -2) SSL_get_new_index(); //Not set yet
			// Set to verify peer.
			SSL_set_ex_data(sslh, sslctx_appdata, (void *)vio);
			SSL_set_verify(sslh, SSL_VERIFY_PEER, &aegaeon_verify_callback);
		}

#endif

		break;
	}

	freeaddrinfo(resultnull);

	if (error || connerror) {
		return (0 - (error | (connerror << 8)));
	} else return 0;

}

critcl::cproc vio_bind {char* vptrs char* hostname char* servname
                       int hint_flags int hint_family int hint_socktype
                       int hint_protocol} int {
	//We have to somehow convert this mess of stuff into an ops->bind() call.
	unsigned long vptr = strtoul(vptrs, NULL, 16);
	mowgli_vio_t *vio = (mowgli_vio_t *) vptr;
#ifdef HAVE_OPENSSL
	SSL_CTX *ctx;
#endif

	mowgli_vio_sockaddr_t *vsockaddr;

	struct addrinfo *hints, *r, *resultnull;
	int error, connerror;

	error = connerror = 0;

	hints = (struct addrinfo *)malloc(sizeof(struct addrinfo));
	hints->ai_family = hint_family;
	hints->ai_socktype = hint_socktype;
	error = getaddrinfo(hostname, servname, hints, &resultnull);

	if (error) return (0 - error);

	for (r = resultnull; r != NULL; r = r->ai_next) {
		mowgli_vio_sockaddr_from_struct(vsockaddr, r->ai_addr, r->ai_addrlen);

		if ((connerror = vio->ops->bind(vio, vsockaddr)) != 0) {
			continue;
		}

#ifdef HAVE_OPENSSL

		if ((ctx = mowgli_vio_openssl_getsslcontext(vio)) != NULL) {
			if (sslctx_appdata == -2) SSL_CTX_get_new_index(); //Not set yet
			// Set to verify peer. Script set will decide whether
			// to wave past.
			SSL_CTX_set_ex_data(ctx, sslctx_appdata, (void *)vio);
			SSL_CTX_set_verify(ctx, SSL_VERIFY_PEER, &aegaeon_verify_callback);
		}

#endif

		break;
	}

	freeaddrinfo(resultnull);

	if (error || connerror) {
		return (0 - (error | (connerror << 8)));
	} else return 0;

}

critcl::cproc vio_recv {Tcl_Interp* interp char* vptrs int maxlen
                     object name1 object name2} int {
	unsigned long vptr = strtoul(vptrs, NULL, 16);
	mowgli_vio_t *vio = (mowgli_vio_t *) vptr;

	int i, error, readbytes;
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
				break;
		}
		if (!error) {
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

	switch (vio->ops->write(vio, input, len)) {
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
critcl::load
