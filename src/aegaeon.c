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

typedef struct {
	char *verify_script;
} aegaeon_ssldata;

void aegaeon_react (mowgli_eventloop_t *el,
	mowgli_eventloop_io_t *elio, mowgli_eventloop_io_dir_t direction,
	void *userdata)
{
	aegaeon_userdata *ud = (aegaeon_userdata *)userdata;
	char *tcl_eventfunc;

	switch (dir) {
		case MOWGLI_EVENTLOOP_IO_READ:
			tcl_eventfunc = ud->read;
			break;
		case MOWGLI_EVENTLOOP_IO_WRITE:
			tcl_eventfunc = ud->write;
			break;
	}

	if (tcl_eventfunc != NULL) Tcl_Eval(ud->interp, tcl_eventfunc);
};

#ifdef HAVE_OPENSSL

int aegaeon_verify_callback (int wavepast, void *context)
{
	// the verify script will be concatenated with the wavepast.
	// it won't be given any more info, just whether or not the cert
	// was deemed valid by OpenSSL, the cert itself, and a
	// symbolic name that will be listed in the docs that explains the
	// matter.
	char *script = malloc(769);
	memset(script, 0, 769);
	mowgli_vio_t *vio = SSL_CTX_get_ex_data(ctx, sslctx_appdata);

	snprintf(script, 768, "%s %d");
}
#endif
