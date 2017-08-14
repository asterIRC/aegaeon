// from the Tcl:
/*
#include <sys/types.h>
#include <sys/socket.h>
#include <fcntl.h>
#include <sys/errno.h>
#include <netinet/in.h>
#include <mowgli.h>
#include <uthash.h>
#include <netdb.h>

typedef struct {
	int fd;
	mowgli_vio_t vio;
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

 */

#include <sys/types.h>
#include <sys/socket.h>
#include <openssl/ssl.h>
#include <openssl/evp.h>
#include <openssl/err.h>
#include <openssl/x509.h>
#include <openssl/x509_vfy.h>
#include <fcntl.h>
#include <sys/errno.h>
#include <netinet/in.h>
#include <libmowgli-2/mowgli.h>
#include <uthash.h>
#include <netdb.h>
extern const char * const sys_errlist[];
extern const int sys_nerr;

typedef struct _aegaeon_handle {
	char handle[35]; // for 128-bit systems, including 0x
	UT_hash_handle hh;
} aegaeon_handle_t;

aegaeon_handle_t *handles = NULL;

void addhandle(char *handle) {
	aegaeon_handle_t *hand = malloc(sizeof(aegaeon_handle_t));
	memset(hand, 0, sizeof(aegaeon_handle_t));
	strncpy(hand->handle, handle, 35);
	aegaeon_handle_t *existshand = NULL;

	HASH_FIND_STR(handles, handle, existshand);

	if (existshand != NULL) return;

	HASH_ADD_STR(handles, handle, hand);
}

void delhandle(char *handle) {
	aegaeon_handle_t *hand = NULL;

	HASH_FIND_STR(handles, handle, hand);

	if (hand == NULL) return;
	HASH_DEL(handles, hand);
}

int isvalidhandle(char *handle) {
	aegaeon_handle_t *hand = NULL;

	HASH_FIND_STR(handles, handle, hand);

	if (hand != NULL)
		return 1;
	else
	{
		return 0;
	}

}

// As a temporary measure... A strerror that internally uses strerror_r
// like the original one does, but tries to be sane about it

char *_strerror(int tryerrlist, int err) {
	char* errstr = malloc(2048*sizeof(unsigned char));

	strerror_r(err, errstr, 2048);
	if (errno != EINVAL) return errstr;
	else if (!tryerrlist) {
		snprintf(errstr, 2048, "Error %d not translatable. strerror_r gave us nothing to work with!", err);
		return errstr;
	} else if (err < sys_nerr) {
		strlcpy(errstr, sys_errlist[err], 2048);
	} else {
		snprintf(errstr, 2048, "Error %d not translatable. neither strerror_r or sys_errlist gave us anything to work with!", err);
	}
	// reach this? die
	snprintf(errstr, 2048, "Error %d not translatable. Reached impossible portion of function!", err);
	return errstr;
}

char *strerror(int err) {return _strerror(1, err);}

extern void mowgli_log_bootstrap(void);
extern void mowgli_node_bootstrap(void);
extern void mowgli_queue_bootstrap(void);
extern void mowgli_object_class_bootstrap(void);
extern void mowgli_argstack_bootstrap(void);
extern void mowgli_bitvector_bootstrap(void);
extern void mowgli_global_storage_bootstrap(void);
extern void mowgli_hook_bootstrap(void);
extern void mowgli_random_bootstrap(void);
extern void mowgli_allocation_policy_bootstrap(void);
extern void mowgli_allocator_bootstrap(void);
extern void mowgli_memslice_bootstrap(void);
extern void mowgli_cacheline_bootstrap(void);
extern void mowgli_interface_bootstrap(void);


typedef struct
{
	SSL *ssl_handle;
	SSL_CTX *ssl_context;
	mowgli_vio_ssl_settings_t settings;
} mowgli_ssl_connection_t;

typedef struct {
	Tcl_Obj *verify_script; // of type list, probably
} aegaeon_ssldata;

void aegaeon_react (mowgli_eventloop_t *el,
	mowgli_eventloop_io_t *elio, mowgli_eventloop_io_dir_t direction,
	void *userdata)
{
	aegaeon_userdata *ud = (aegaeon_userdata *)userdata;
	Tcl_Obj *tcl_eventfunc;

	switch (direction) {
		case MOWGLI_EVENTLOOP_IO_READ:
			tcl_eventfunc = ud->read;
			break;
		case MOWGLI_EVENTLOOP_IO_WRITE:
			tcl_eventfunc = ud->write;
			break;
		case MOWGLI_EVENTLOOP_IO_ERROR:
			tcl_eventfunc = ud->error;
			break;
	}

	// We expect the user to have used [list].

	if (tcl_eventfunc != NULL) Tcl_EvalObjEx(ud->interp, tcl_eventfunc, TCL_EVAL_GLOBAL);
};

void aegaeon_tick (void *userdata)
{
	aegaeon_userdata *ud = (aegaeon_userdata *)userdata;
	Tcl_Obj *tcl_eventfunc = Tcl_DuplicateObj(ud->read);

	// We expect the user to have used [list], but will append ->write for them.

	if (ud->write != NULL) Tcl_ListObjAppendElement(ud->interp, tcl_eventfunc, ud->write);

	if (tcl_eventfunc != NULL) Tcl_EvalObjEx(ud->interp, tcl_eventfunc, TCL_EVAL_GLOBAL);

	if (*(int *)(ud->privdata) == 0) {
		Tcl_DecrRefCount(ud->read);
		Tcl_DecrRefCount(ud->write);
		free(ud->privdata);
	};
};

int aegaeon_verify_callback (int wavepast, X509_STORE_CTX *context)
{
	// the verify script will be concatenated with the wavepast.
	// it won't be given any more info, just whether or not the cert
	// was deemed valid by OpenSSL, and a handle to the x509 itself, and
	// a number explaining the situation.
	SSL *sslh = X509_STORE_CTX_get_ex_data(context, SSL_get_ex_data_X509_STORE_CTX_idx());

	mowgli_vio_t *vio = SSL_get_ex_data(sslh, sslctx_appdata);
	char *sarg[3];
	if (vio == NULL) {
		printf("Aaahh! Dead verify [vio is NULL], aborting connection! This is probably a bug\n\nDebug information: sslctx_appdata = %d\n\n", sslctx_appdata);
		return 0; // Shouldn't happen
	}
	aegaeon_userdata *ud = vio->userdata;
	aegaeon_ssldata *ssld = ud->privdata;
	if (ssld->verify_script == NULL) {
		printf("Aaahh! Dead verify [verify_script is NULL], accepting OpenSSL's decision as gospel truth! This is probably a bug\n\nDebug information: sslctx_appdata = %d\n"
			"wavepast = %d" "\n", sslctx_appdata, wavepast);
		return wavepast;
	}
	Tcl_Obj *scr = Tcl_DuplicateObj(ssld->verify_script);
	Tcl_IncrRefCount(scr);

	sarg[0] = malloc(26);
	memset(sarg[0], 0, 26);
	snprintf (sarg[0], 25, "%d", wavepast);

	X509 *certificant = X509_STORE_CTX_get_current_cert(context);

	sarg[1] = malloc(41);
	memset(sarg[1], 0, 41);
	snprintf (sarg[1], 40, "%p", certificant);
	addhandle(sarg[1]);

	sarg[2] = malloc(26);
	memset(sarg[2], 0, 26);
	snprintf (sarg[2], 25, "%d", X509_STORE_CTX_get_error(context));

	Tcl_ListObjAppendElement(ud->interp, scr, Tcl_NewStringObj(sarg[0], strlen(sarg[0])));
	Tcl_ListObjAppendElement(ud->interp, scr, Tcl_NewStringObj(sarg[1], strlen(sarg[1])));
	Tcl_ListObjAppendElement(ud->interp, scr, Tcl_NewStringObj(sarg[2], strlen(sarg[2])));

	Tcl_EvalObjEx(ud->interp, scr, 0);

	Tcl_ObjSetVar2(ud->interp, Tcl_NewStringObj("hate", 4), Tcl_NewStringObj("hate", 4), scr, 0);

	const char *verifiedres = Tcl_GetStringResult(ud->interp);
	unsigned long verified = strtoul(verifiedres, NULL, 10);
	printf ("Verification information:\n" "string result of verification: %s\n" "integer result of verification: %lu\n", verifiedres, verified);
	return verified;
}

void aegaeon_mowgli_log_cb (const char *logline)
{
	//write(2, logline, strlen(logline));
	//write(2, "\r\n", 2);
	return;
}

// lifted from mowgli's stuff

int aegaeon_vio_error(mowgli_vio_t *vio)
{
	const char *errtype;

	switch (vio->error.op)
	{
	case MOWGLI_VIO_ERR_OP_READ:
		errtype = "Read";
		break;
	case MOWGLI_VIO_ERR_OP_WRITE:
		errtype = "Write";
		break;
	case MOWGLI_VIO_ERR_OP_LISTEN:
		errtype = "Listen";
		break;
	case MOWGLI_VIO_ERR_OP_ACCEPT:
		errtype = "Accept";
		break;
	case MOWGLI_VIO_ERR_OP_CONNECT:
		errtype = "Connect";
		break;
	case MOWGLI_VIO_ERR_OP_SOCKET:
		errtype = "Socket";
		break;
	case MOWGLI_VIO_ERR_OP_BIND:
		errtype = "Bind";
		break;
	case MOWGLI_VIO_ERR_OP_OTHER:
		errtype = "Application";
		break;
	default:
		errtype = "Generic/Unknown";
	}

	aegaeon_userdata *ud = (aegaeon_userdata *)vio->userdata;

	if (ud->error == NULL) return -1;

	Tcl_Obj *scr = Tcl_DuplicateObj(ud->error);

	Tcl_ListObjAppendElement(ud->interp, scr, Tcl_NewStringObj(errtype, strlen(errtype)));
	Tcl_ListObjAppendElement(ud->interp, scr, Tcl_NewStringObj(vio->error.string, strlen(vio->error.string)));

	char *sarg[2];
	sarg[0] = malloc(21);
	memset(sarg[0], 0, 21);
	snprintf (sarg[0], 21, "%lu", vio->error.code);

	sarg[1] = malloc(21);
	memset(sarg[1], 0, 21);
	snprintf (sarg[1], 21, "%d", vio->error.op);

	Tcl_ListObjAppendElement(ud->interp, scr, Tcl_NewStringObj(sarg[0], strlen(sarg[0])));
	Tcl_ListObjAppendElement(ud->interp, scr, Tcl_NewStringObj(sarg[1], strlen(sarg[1])));

	// We trust user used [list].

	Tcl_EvalObjEx(ud->interp, scr, TCL_EVAL_GLOBAL);

	return -1;
}

int
aegaeon_openssl_trickery(mowgli_vio_t *vio, mowgli_ssl_connection_t *connection)
{
	if (sslctx_appdata == -2) sslctx_appdata = SSL_get_ex_new_index(0, "verification callback storage", NULL, NULL, NULL); //Not set yet
	SSL_set_ex_data(connection->ssl_handle, sslctx_appdata, (void *)vio);
	SSL_set_verify(connection->ssl_handle, SSL_VERIFY_PEER, &aegaeon_verify_callback);
	if (connection->settings.cert_path != NULL && connection->settings.privatekey_path != NULL) {
		if (SSL_CTX_use_certificate_file(connection->ssl_context, connection->settings.cert_path, SSL_FILETYPE_PEM) != 1)
			return mowgli_vio_err_sslerrcode(vio, ERR_get_error());

		if (SSL_CTX_use_PrivateKey_file(connection->ssl_context, connection->settings.privatekey_path, SSL_FILETYPE_PEM) != 1)
			return mowgli_vio_err_sslerrcode(vio, ERR_get_error());
	}
	return 0;
}

int
aegaeon_mowgli_vio_openssl_client_handshake(mowgli_vio_t *vio, mowgli_ssl_connection_t *connection)
{
	const int fd = mowgli_vio_getfd(vio);
	int ret;

	vio->error.op = MOWGLI_VIO_ERR_OP_CONNECT;

#ifndef MOWGLI_HAVE_OPENSSL_TLS_METHOD_API
	connection->ssl_context = SSL_CTX_new(SSLv23_client_method());
#else
	connection->ssl_context = SSL_CTX_new(TLS_client_method());
#endif

	if (connection->ssl_context == NULL)
		return mowgli_vio_err_sslerrcode(vio, ERR_get_error());

#ifndef MOWGLI_HAVE_OPENSSL_TLS_METHOD_API
#  ifdef SSL_OP_NO_SSLv2
	SSL_CTX_set_options(connection->ssl_context, SSL_OP_NO_SSLv2);
#  endif
#  ifdef SSL_OP_NO_SSLv3
	SSL_CTX_set_options(connection->ssl_context, SSL_OP_NO_SSLv3);
#  endif
#endif

	connection->ssl_handle = SSL_new(connection->ssl_context);

	if (connection->ssl_handle == NULL)
		return mowgli_vio_err_sslerrcode(vio, ERR_get_error());

	aegaeon_openssl_trickery(vio, connection);

	SSL_set_connect_state(connection->ssl_handle);

	if (!SSL_set_fd(connection->ssl_handle, fd))
		return mowgli_vio_err_sslerrcode(vio, ERR_get_error());

	if (vio->eventloop)
		SSL_CTX_set_mode(connection->ssl_context, SSL_MODE_ENABLE_PARTIAL_WRITE);

	if ((ret = SSL_connect(connection->ssl_handle)) != 1)
	{
		unsigned long err = SSL_get_error(connection->ssl_handle, ret);

		if (err == SSL_ERROR_WANT_READ)
		{
			mowgli_vio_setflag(vio, MOWGLI_VIO_FLAGS_NEEDREAD, true);
			MOWGLI_VIO_SETREAD(vio)
		}
		else if (err == SSL_ERROR_WANT_WRITE)
		{
			mowgli_vio_setflag(vio, MOWGLI_VIO_FLAGS_NEEDWRITE, true);
			MOWGLI_VIO_SETWRITE(vio)
		}
		else if (err == SSL_ERROR_WANT_CONNECT)
		{
			mowgli_vio_setflag(vio, MOWGLI_VIO_FLAGS_ISCONNECTING, true);
			return 0;
		}
		else
		{
			return mowgli_vio_err_sslerrcode(vio, err);
		}

		mowgli_vio_setflag(vio, MOWGLI_VIO_FLAGS_ISSSLCONNECTING, false);
		return 0;
	}

	/* Connected */
	mowgli_vio_setflag(vio, MOWGLI_VIO_FLAGS_ISSSLCONNECTING, false);

	vio->error.op = MOWGLI_VIO_ERR_OP_NONE;
	return 0;
}


int
aegaeon_mowgli_vio_openssl_connect(mowgli_vio_t *vio, mowgli_vio_sockaddr_t *addr)
{
	const int fd = mowgli_vio_getfd(vio);

	return_val_if_fail(fd != -1, -255);

	mowgli_ssl_connection_t *connection = vio->privdata;

	vio->error.op = MOWGLI_VIO_ERR_OP_CONNECT;

	if (connect(fd, (struct sockaddr *) &addr->addr, addr->addrlen) < 0)
	{
		if (!mowgli_eventloop_ignore_errno(errno))
		{
			return mowgli_vio_err_errcode(vio, strerror, errno);
		}
		else
		{
			mowgli_vio_setflag(vio, MOWGLI_VIO_FLAGS_ISCONNECTING, true);
			mowgli_vio_setflag(vio, MOWGLI_VIO_FLAGS_ISSSLCONNECTING, true);
			vio->error.op = MOWGLI_VIO_ERR_OP_NONE;
			return 0;
		}
	}

	memcpy(&vio->addr.addr, &addr->addr, addr->addrlen);
	vio->addr.addrlen = addr->addrlen;

	mowgli_vio_setflag(vio, MOWGLI_VIO_FLAGS_ISCLIENT, true);
	mowgli_vio_setflag(vio, MOWGLI_VIO_FLAGS_ISSERVER, false);

	/* Non-blocking socket, begin handshake */
	mowgli_vio_setflag(vio, MOWGLI_VIO_FLAGS_ISCONNECTING, false);
	return aegaeon_mowgli_vio_openssl_client_handshake(vio, connection);
}
