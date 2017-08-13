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
#include <fcntl.h>
#include <sys/errno.h>
#include <netinet/in.h>
#include <libmowgli-2/mowgli.h>
#include <uthash.h>
#include <netdb.h>
extern const char * const sys_errlist[];
extern const int sys_nerr;


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

	Tcl_ListObjAppendElement(ud->interp, tcl_eventfunc, ud->write);

	if (tcl_eventfunc != NULL) Tcl_EvalObjEx(ud->interp, tcl_eventfunc, TCL_EVAL_GLOBAL);

	if (*(int *)(ud->privdata) == 0) {
		Tcl_DecrRefCount(ud->read);
		Tcl_DecrRefCount(ud->write);
		free(ud->privdata);
	};
};

#ifdef HAVE_OPENSSL

int aegaeon_verify_callback (int wavepast, X509_STORE_CTX *context)
{
	// the verify script will be concatenated with the wavepast.
	// it won't be given any more info, just whether or not the cert
	// was deemed valid by OpenSSL, and a handle to the x509 itself, and
	// a number explaining the situation.
	SSL *sslh = X509_STORE_CTX_get_ex_data(context, SSL_get_ex_data_X509_STORE_CTX_idx());

	mowgli_vio_t *vio = SSL_CTX_get_ex_data(context, sslctx_appdata);
	char *sarg[3];
	Tcl_Obj *scr = Tcl_DuplicateObj((aegaeon_userdata *)(vio->userdata)->privdata)->verify_script;

	sarg[0] = malloc(26);
	memset(sarg[0], 0, 26);
	snprintf (sarg[0], 25, "%d", wavepast);

	sarg[1] = malloc(41);
	memset(sarg[1], 0, 41);
	snprintf (sarg[1], 40, "0x%lx", (unsigned long *)context);

	sarg[2] = malloc(26);
	memset(sarg[2], 0, 26);
	snprintf (sarg[2], 25, "%d", X509_STORE_CTX_get_error);

	Tcl_ListObjAppendElement((aegaeon_userdata *)(vio->userdata)->interp, scr, Tcl_NewStringObj(sarg[0], strlen(sarg[0])));
	Tcl_ListObjAppendElement((aegaeon_userdata *)(vio->userdata)->interp, scr, Tcl_NewStringObj(sarg[1], strlen(sarg[1])));
	Tcl_ListObjAppendElement((aegaeon_userdata *)(vio->userdata)->interp, scr, Tcl_NewStringObj(sarg[2], strlen(sarg[2])));

	Tcl_EvalObjEx(ud->interp, scr, TCL_EVAL_GLOBAL);
}
#endif

void aegaeon_mowgli_log_cb (const char *logline)
{
	write(2, logline, strlen(logline));
	write(2, "\r\n", 2);
}
