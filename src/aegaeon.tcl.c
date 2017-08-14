# -*- syntax: tcl -*-
package require critcl
package provide aegaeon 0.01.0.1

if {![critcl::compiling]} {exit}

if {0} {
/*
 * Copyright (c) 2017 the management of umbrellix.net
 *
 * Permission to use, copy, modify, and/or distribute this software for any
 * purpose with or without fee is hereby granted, provided that the above
 * copyright notice and this permission notice appear in all copies.
 *
 * THIS SOFTWARE IS PROVIDED BY THE AUTHOR ``AS IS'' AND ANY EXPRESS OR
 * IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE IMPLIED
 * WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE ARE
 * DISCLAIMED. IN NO EVENT SHALL THE AUTHOR BE LIABLE FOR ANY DIRECT,
 * INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL DAMAGES
 * (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS OR
 * SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS INTERRUPTION)
 * HOWEVER CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN CONTRACT,
 * STRICT LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING
 * IN ANY WAY OUT OF THE USE OF THIS SOFTWARE, EVEN IF ADVISED OF THE
 * POSSIBILITY OF SUCH DAMAGE.
 */
}

critcl::source ../critflags.tcl

critcl::cflags -g -fPIC -DPIC -std=gnu99 -I /usr/home/hadron/src/aegaeon/libmowgli-2/run/include -O0 -g
critcl::ldflags -lssl -L/usr/lib -L/usr/local/lib

critcl::cheaders /usr/home/hadron/src/aegaeon/libmowgli-2/run/include

critcl::ccode {
#include <sys/types.h>
#include <sys/socket.h>
#include <openssl/ssl.h>
#include <openssl/evp.h>
#include <openssl/bio.h>
#include <fcntl.h>
#include <stdio.h>
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

#define AEGAEON_MD2 1
#define AEGAEON_MD4 2
#define AEGAEON_MD5 3
#define AEGAEON_SHA1 4
#define AEGAEON_SHA224 5
#define AEGAEON_SHA256 6
#define AEGAEON_SHA384 7
#define AEGAEON_SHA512 8
#define AEGAEON_RAWDER 9

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

::critcl::cdefines [list PF_* AF_* IPPROTO_* SOCK_* X509_V_* MOWGLI_* SOMAXCONN AEGAEON_*]

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

	Tcl_Obj *outobj = Tcl_NewByteArrayObj(output, i);

	//Tcl_IncrRefCount(outobj); // may be unneeded

	Tcl_ObjSetVar2(interp, name1, name2, outobj, 0);

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
	snprintf(o, 40, "%p", el);
	addhandle(o);
	return o;
}

critcl::cproc eventloop_crank {char* elptrs} void {
	if (!isvalidhandle(elptrs)) return;
	unsigned long elptr = strtoul(elptrs, NULL, 16);
	mowgli_eventloop_t *el = (mowgli_eventloop_t *) elptr;

	mowgli_eventloop_run_once(el);
}

critcl::cproc eventloop_fire {char* elptrs} void {
	if (!isvalidhandle(elptrs)) return;
	unsigned long elptr = strtoul(elptrs, NULL, 16);
	mowgli_eventloop_t *el = (mowgli_eventloop_t *) elptr;

	mowgli_eventloop_run(el);
}

critcl::cproc timer_add {Tcl_Interp* interp char* elptrs char* name
                         object script object arg int every} dstring {
	char *o = Tcl_Alloc(40);
	memset(o, 0, 40);

	if (!isvalidhandle(elptrs)) {
		strncpy(o, "0x0", 3);
		return o;
	}

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
	snprintf(o, 40, "%p", elt);

	addhandle(o);
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
	vio->ops->error = &aegaeon_vio_error;
	snprintf(o, 40, "%p", vio);
	addhandle(o);
	return o;
}

critcl::cproc tls_get_fp {Tcl_Interp* interp char* x509ptrs int hashtype} object {
	if (!isvalidhandle(x509ptrs)) {
		Tcl_Obj *retv = Tcl_NewByteArrayObj(strdup(""), 0);
		Tcl_IncrRefCount(retv);
		return retv;
	}
	unsigned long x509ptr = strtoul(x509ptrs, NULL, 16);
	X509 *x509 = (X509 *)x509ptr;
	int length, encode;
	unsigned char *buf, *ptr;
	EVP_MD* hashfunc = NULL;

	encode = length = 0;

	switch (hashtype) {
		case AEGAEON_RAWDER:
			length = i2d_X509(x509, NULL);
			encode = 0;
			break;
#ifndef OPENSSL_NO_MD2
		case AEGAEON_MD2:
			length = 16;
			encode = 1;
			hashfunc = EVP_md2();
			break;
#endif
#ifndef OPENSSL_NO_MD4
		case AEGAEON_MD4:
			length = 16;
			encode = 1;
			hashfunc = EVP_md4();
			break;
#endif
#ifndef OPENSSL_NO_MD5
		case AEGAEON_MD5:
			length = 16;
			encode = 1;
			hashfunc = EVP_md5();
			break;
#endif
#ifndef OPENSSL_NO_SHA1
		case AEGAEON_SHA1:
			length = 20;
			encode = 1;
			hashfunc = EVP_sha1();
			break;
#endif
#ifndef OPENSSL_NO_SHA256
		case AEGAEON_SHA224:
			length = 28;
			encode = 1;
			hashfunc = EVP_sha224();
			break;
		case AEGAEON_SHA256:
			length = 32;
			encode = 1;
			hashfunc = EVP_sha256();
			break;
#endif
#ifndef OPENSSL_NO_SHA512
		case AEGAEON_SHA384:
			length = 48;
			encode = 1;
			hashfunc = EVP_sha384();
			break;
		case AEGAEON_SHA512:
			length = 64;
			encode = 1;
			hashfunc = EVP_sha512();
			break;
#endif
	}

	if (encode) {
		buf = Tcl_Alloc(length);
		X509_digest(x509, hashfunc, buf, &length);
	} else {
		buf = Tcl_Alloc(length);
		ptr = buf;
		i2d_X509(x509, &ptr);
	}

	Tcl_Obj *retv = Tcl_NewByteArrayObj(buf, length);
	Tcl_IncrRefCount(retv);
	return retv;
}

critcl::cproc vio_tls_socket {char* vptrs int family int type int proto object vcallback} int {
	if (!isvalidhandle(vptrs)) return -255;
	unsigned long vptr = strtoul(vptrs, NULL, 16);
	mowgli_vio_t *vio = (mowgli_vio_t *) vptr;
	aegaeon_ssldata *verify_script = malloc(sizeof(aegaeon_ssldata));
	memset(verify_script, 0, sizeof(aegaeon_ssldata));

	verify_script->verify_script = vcallback;
	Tcl_IncrRefCount(vcallback);

	((aegaeon_userdata *)(vio->userdata))->privdata = (void *)verify_script;

	mowgli_vio_openssl_setssl(vio, NULL, NULL);
	mowgli_vio_ops_set_op(vio->ops, connect, aegaeon_mowgli_vio_openssl_connect);
	return vio->ops->socket(vio, family, type, proto);
}

critcl::cproc vio_tls_our_cert {char* vptrs char* certpath char* keypath} int {
	if (!isvalidhandle(vptrs)) return -255;
	unsigned long vptr = strtoul(vptrs, NULL, 16);
	mowgli_vio_t *vio = (mowgli_vio_t *) vptr;

	if (((aegaeon_ssldata *)((aegaeon_userdata *)(vio->userdata))->privdata)->verify_script == NULL) return -255; // Invalid operation
	// on non-SSL socket

	mowgli_ssl_connection_t *connection = (mowgli_ssl_connection_t *)vio->privdata;

	if (strlen(keypath) == 0) keypath = certpath;

	connection->settings.cert_path = certpath;
	connection->settings.privatekey_path = keypath;

	return 0;
}

critcl::cproc vio_socket {char* vptrs int family int type int proto} int {
	if (!isvalidhandle(vptrs)) return -255;
	unsigned long vptr = strtoul(vptrs, NULL, 16);
	mowgli_vio_t *vio = (mowgli_vio_t *) vptr;
	return vio->ops->socket(vio, family, type, proto);
}

critcl::cproc vio_listen {char* vptrs int backlog} int {
	if (!isvalidhandle(vptrs)) return -255;
	unsigned long vptr = strtoul(vptrs, NULL, 16);
	mowgli_vio_t *vio = (mowgli_vio_t *) vptr;
	return vio->ops->listen(vio, backlog);
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
	if (!isvalidhandle(vptrs)) return;
	if (!isvalidhandle(elptrs)) return;
	unsigned long vptr = strtoul(vptrs, NULL, 16);
	mowgli_vio_t *vio = (mowgli_vio_t *) vptr;

	unsigned long elptr = strtoul(elptrs, NULL, 16);
	mowgli_eventloop_t *el = (mowgli_eventloop_t *) elptr;

	mowgli_vio_eventloop_attach(vio, el, &aegaeon_evops);
	MOWGLI_VIO_SETREAD(vio);
	MOWGLI_VIO_SETWRITE(vio);
}

critcl::cproc vio_destroy {char* vptrs} void {
	if (!isvalidhandle(vptrs)) return;
	unsigned long vptr = strtoul(vptrs, NULL, 16);
	mowgli_vio_t *vio = (mowgli_vio_t *) vptr;
	mowgli_vio_destroy(vio);
	return;
}

critcl::cproc timer_destroy {char* elptrs char* tptrs} void {
	if (!isvalidhandle(elptrs)) return;
	if (!isvalidhandle(tptrs)) return;
	unsigned long elptr = strtoul(elptrs, NULL, 16);
	mowgli_eventloop_t *el = (mowgli_eventloop_t *) elptr;

	unsigned long tptr = strtoul(tptrs, NULL, 16);
	mowgli_eventloop_timer_t *t = (mowgli_eventloop_timer_t *) tptr;

	mowgli_timer_destroy(el, t);
	return;
}

critcl::cproc vio_eventloop_detach {char* vptrs} void {
	if (!isvalidhandle(vptrs)) return;
	unsigned long vptr = strtoul(vptrs, NULL, 16);
	mowgli_vio_t *vio = (mowgli_vio_t *) vptr;
	mowgli_vio_eventloop_detach(vio);
	return;
}

critcl::cproc vio_connect {char* vptrs char* hostname char* servname
                       int hint_flags int hint_family int hint_socktype
                       int hint_protocol} int {
	//We have to somehow convert this mess of stuff into an ops->connect() call.
	if (!isvalidhandle(vptrs)) return -255;
	unsigned long vptr = strtoul(vptrs, NULL, 16);
	mowgli_vio_t *vio = (mowgli_vio_t *) vptr;
	SSL_CTX *sslctx; SSL *sslh;

	mowgli_vio_sockaddr_t *vsockaddr = malloc(sizeof(mowgli_vio_sockaddr_t));

	struct addrinfo hints, *r, *resultnull;
	int error, connerror;

	error = connerror = 0;

	memset(&hints, 0, sizeof(hints));
	hints.ai_family = hint_family;
	hints.ai_socktype = hint_socktype;
	hints.ai_protocol = hint_protocol;
	error = getaddrinfo(hostname, servname, &hints, &resultnull);

	if (error) return (0 - error);

	char *dprlu = malloc(52*sizeof(char));
	memset(dprlu, 0, 52);

	for (r = resultnull; r != NULL; r = r->ai_next) {
		mowgli_vio_sockaddr_from_struct(vsockaddr, r->ai_addr, r->ai_addrlen);

		if ((connerror = vio->ops->connect(vio, vsockaddr)) != 0) {
			continue;
		}

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
	if (!isvalidhandle(vptrs)) return -255;
	unsigned long vptr = strtoul(vptrs, NULL, 16);
	mowgli_vio_t *vio = (mowgli_vio_t *) vptr;
	SSL *sslh;

	mowgli_vio_sockaddr_t vsockaddr;

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
		mowgli_vio_sockaddr_from_struct(&vsockaddr, r->ai_addr, sizeof(*(r->ai_addr)));

		if ((connerror = vio->ops->bind(vio, &vsockaddr)) != 0) {
			continue;
		}

		break;
	}

	freeaddrinfo(resultnull);

	if (error || connerror) {
		return (0 - (error | (connerror << 8)));
	} else return 0;

}

critcl::cproc vio_recv {Tcl_Interp* interp char* vptrs int maxlen
                     object name1 object name2} int {
	if (!isvalidhandle(vptrs)) return -255;
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
				error = vio->error.code;
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
	} while(0);

	Tcl_ObjSetVar2(interp, name1, name2, Tcl_NewByteArrayObj(output, readbytes), 0);

	return readbytes;
}

critcl::cproc vio_send {Tcl_Interp* interp char* vptrs char* stringtosend} int {
	if (!isvalidhandle(vptrs)) return -255;
	unsigned long vptr = strtoul(vptrs, NULL, 16);
	mowgli_vio_t *vio = (mowgli_vio_t *) vptr;

	int len, error;

	return vio->ops->write(vio, stringtosend, strlen(stringtosend));
}

critcl::cproc vio_strerror {char* vptrs} vstring {
	if (!isvalidhandle(vptrs)) return strerror(EINVAL);
	unsigned long vptr = strtoul(vptrs, NULL, 16);
	mowgli_vio_t *vio = (mowgli_vio_t *) vptr;

	return vio->error.string;
}

# Lifted from core/bootstrap.c because we seem to need it

critcl::cproc mowgli_bootstrap {} void {
	static bool bootstrapped = 0;

	if (bootstrapped)
		return;

	/* initial bootstrap */
	mowgli_log_bootstrap();
	mowgli_node_bootstrap();
	mowgli_queue_bootstrap();
	mowgli_object_class_bootstrap();
	mowgli_argstack_bootstrap();
	mowgli_bitvector_bootstrap();
	mowgli_global_storage_bootstrap();
	mowgli_hook_bootstrap();
	mowgli_random_bootstrap();
	mowgli_allocation_policy_bootstrap();
	mowgli_allocator_bootstrap();
	mowgli_memslice_bootstrap();
	mowgli_cacheline_bootstrap();
	mowgli_interface_bootstrap();

#ifdef _WIN32
	extern void mowgli_winsock_bootstrap(void);

	mowgli_winsock_bootstrap();
#endif

	/* now that we're bootstrapped, we can use a more optimised allocator
	   if one is available. */
	mowgli_allocator_set_policy(mowgli_allocator_malloc);

	bootstrapped = true;
}
critcl::load
