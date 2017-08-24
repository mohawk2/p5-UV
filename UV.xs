#include "EXTERN.h"
#include "perl.h"
#include "XSUB.h"

#define NEED_newRV_noinc
#define NEED_newCONSTSUB
#define NEED_sv_2pv_flags
#include "ppport.h"

#define MATH_INT64_NATIVE_IF_AVAILABLE
#include "perl_math_int64.h"
#include <assert.h>
#include <stdlib.h>

#include <uv.h>

#if !defined(UV_DISCONNECT)
#define UV_DISCONNECT 4
#endif
#if !defined(UV_PRIORITIZED)
#define UV_PRIORITIZED 8
#endif
#if !defined(UV_VERSION_HEX)
#define UV_VERSION_HEX  ((UV_VERSION_MAJOR << 16) | \
                         (UV_VERSION_MINOR <<  8) | \
                         (UV_VERSION_PATCH))
#endif
// back-compat for 5.10.0 since it's easy
#ifndef mPUSHs
#  define mPUSHs(sv)  PUSHs(sv_2mortal(sv))
#endif

#define uv_data(h)      ((handle_data_t *)((uv_handle_t *)(h))->data)
#define uv_user_data(h) uv_data(h)->user_data;
#define uv_self(h)      (SV *)(uv_data(h)->self)

/* typedefs for XS return values of T_PTROBJ */
typedef uv_check_t * UV__Check;
typedef uv_handle_t * UV__Handle;
typedef uv_idle_t * UV__Idle;
typedef uv_loop_t * UV__Loop;
typedef uv_poll_t * UV__Poll;
typedef uv_prepare_t * UV__Prepare;
typedef uv_timer_t * UV__Timer;

/* data to store with a HANDLE */
typedef struct handle_data_s {
    SV *self;
    SV *user_data;
    /* callbacks available */
    SV *alloc_cb;
    SV *check_cb;
    SV *close_cb;
    SV *idle_cb;
    SV *poll_cb;
    SV *prepare_cb;
    SV *timer_cb;
} handle_data_t;

static SV * s_get_cv (SV *cb_sv)
{
    dTHX;
    HV *st;
    GV *gvp;

    return (SV *)sv_2cv(cb_sv, &st, &gvp, 0);
}

static SV * s_get_cv_croak (SV *cb_sv)
{
    SV *cv = s_get_cv(cb_sv);

    if (!cv) {
        dTHX;
        croak("%s: callback must be a CODE reference or another callable object", SvPV_nolen(cb_sv));
    }

    return cv;
}

/* Handle function definitions for some that aren't alpha ordered later */
static void handle_alloc_cb(uv_handle_t* handle, size_t suggested_size, uv_buf_t* buf);
static void handle_check_cb(uv_check_t* handle);
static void handle_close_cb(uv_handle_t* handle);
static void handle_idle_cb(uv_idle_t* handle);
static const char* handle_namespace(const uv_handle_type type);
static void handle_poll_cb(uv_poll_t* handle, int status, int events);
static void handle_prepare_cb(uv_prepare_t* handle);
static void handle_timer_cb(uv_timer_t* handle);
static void loop_walk_cb(uv_handle_t* handle, void* arg);

/* loop functions */
void loop_default_init(uv_loop_t *default_loop)
{
    if (NULL == default_loop) {
        default_loop = uv_default_loop();
        if (!default_loop) {
            croak("Error getting a new default loop");
        }
    }
}

static uv_loop_t * loop_new()
{
    uv_loop_t *loop;
    int ret;
    Newx(loop, 1, uv_loop_t);
    if (NULL == loop) {
        croak("Unable to allocate space for a new loop");
    }
    ret = uv_loop_init(loop);
    if (0 != ret) {
        Safefree(loop);
        croak("Error initializing loop (%i): %s", ret, uv_strerror(ret));
    }
    return loop;
}

static void loop_walk_cb(uv_handle_t* handle, void* arg)
{
    SV *callback;
    if (NULL == arg || (SV *)arg == &PL_sv_undef) return;
    callback = arg ? s_get_cv_croak((SV *)arg) : NULL;
    if (NULL == callback) return;

    /* provide info to the caller: invocant, suggested_size */
    dSP;
    ENTER;
    SAVETMPS;

    PUSHMARK (SP);
    EXTEND (SP, 1);
    mPUSHs(newSVsv(uv_self(handle))); /* invocant */

    PUTBACK;
    call_sv (callback, G_VOID);
    SPAGAIN;

    FREETMPS;
    LEAVE;
}

/* handle functions */
static void handle_data_destroy(handle_data_t *data_ptr)
{
    if (NULL == data_ptr) return;
    data_ptr->self = NULL;

    /* cleanup any callback references */
    if (NULL != data_ptr->alloc_cb) {
        SvREFCNT_dec(data_ptr->alloc_cb);
        data_ptr->alloc_cb = NULL;
    }
    if (NULL != data_ptr->check_cb) {
        SvREFCNT_dec(data_ptr->check_cb);
        data_ptr->check_cb = NULL;
    }
    if (NULL != data_ptr->close_cb) {
        SvREFCNT_dec(data_ptr->close_cb);
        data_ptr->close_cb = NULL;
    }
    if (NULL != data_ptr->idle_cb) {
        SvREFCNT_dec(data_ptr->idle_cb);
        data_ptr->idle_cb = NULL;
    }
    if (NULL != data_ptr->poll_cb) {
        SvREFCNT_dec(data_ptr->poll_cb);
        data_ptr->poll_cb = NULL;
    }
    if (NULL != data_ptr->prepare_cb) {
        SvREFCNT_dec(data_ptr->prepare_cb);
        data_ptr->prepare_cb = NULL;
    }
    if (NULL != data_ptr->timer_cb) {
        SvREFCNT_dec(data_ptr->timer_cb);
        data_ptr->timer_cb = NULL;
    }
    Safefree(data_ptr);
    data_ptr = NULL;
}

static handle_data_t* handle_data_new(const uv_handle_type type)
{
    handle_data_t *data_ptr = (handle_data_t *)malloc(sizeof(handle_data_t));
    if (NULL == data_ptr) {
        croak("Cannot allocate space for handle data.");
    }

    /* setup the user data */
    data_ptr->user_data = NULL;

    /* setup the callback slots */
    data_ptr->alloc_cb = NULL;
    data_ptr->check_cb = NULL;
    data_ptr->close_cb = NULL;
    data_ptr->idle_cb = NULL;
    data_ptr->poll_cb = NULL;
    data_ptr->prepare_cb = NULL;
    data_ptr->timer_cb = NULL;
    return data_ptr;
}

static void handle_destroy(uv_handle_t *handle)
{
    if (NULL == handle) return;
    if (0 == uv_is_closing(handle) && 0 == uv_is_active(handle)) {
        uv_close(handle, handle_close_cb);
        handle_data_destroy(uv_data(handle));
        /*Safefree(handle);*/
    }
}

static const char * handle_namespace(const uv_handle_type type)
{
    switch (type) {
        case UV_ASYNC: return "UV::Async"; break;
        case UV_CHECK: return "UV::Check"; break;
        case UV_FS_EVENT: return "UV::FSEvent"; break;
        case UV_FS_POLL: return "UV::FSPoll"; break;
        case UV_IDLE: return "UV::Idle"; break;
        case UV_NAMED_PIPE: return "UV::NamedPipe"; break;
        case UV_POLL: return "UV::Poll"; break;
        case UV_PREPARE: return "UV::Prepare"; break;
        case UV_PROCESS: return "UV::Process"; break;
        case UV_STREAM: return "UV::Stream"; break;
        case UV_TCP: return "UV::TCP"; break;
        case UV_TIMER: return "UV::Timer"; break;
        case UV_TTY: return "UV::TTY"; break;
        case UV_UDP: return "UV::UDP"; break;
        case UV_SIGNAL: return "UV::Signal"; break;
        default:
            croak("Invalid handle type supplied");
    }
    return NULL;
}

static uv_handle_t* handle_new(const uv_handle_type type)
{
    uv_handle_t *handle;
    handle_data_t *data_ptr = handle_data_new(type);
    switch (type) {
        case UV_ASYNC: Newxc(handle, 1, uv_async_t, uv_handle_t); break;
        case UV_CHECK: Newxc(handle, 1, uv_check_t, uv_handle_t); break;
        case UV_FS_EVENT: Newxc(handle, 1, uv_fs_event_t, uv_handle_t); break;
        case UV_FS_POLL: Newxc(handle, 1, uv_fs_poll_t, uv_handle_t); break;
        case UV_IDLE: Newxc(handle, 1, uv_idle_t, uv_handle_t); break;
        case UV_NAMED_PIPE: Newxc(handle, 1, uv_pipe_t, uv_handle_t); break;
        case UV_POLL: Newxc(handle, 1, uv_poll_t, uv_handle_t); break;
        case UV_PREPARE: Newxc(handle, 1, uv_prepare_t, uv_handle_t); break;
        case UV_PROCESS: Newxc(handle, 1, uv_process_t, uv_handle_t); break;
        case UV_STREAM: Newxc(handle, 1, uv_stream_t, uv_handle_t); break;
        case UV_TCP: Newxc(handle, 1, uv_tcp_t, uv_handle_t); break;
        case UV_TIMER: Newxc(handle, 1, uv_timer_t, uv_handle_t); break;
        case UV_TTY: Newxc(handle, 1, uv_tty_t, uv_handle_t); break;
        case UV_UDP: Newxc(handle, 1, uv_udp_t, uv_handle_t); break;
        case UV_SIGNAL: Newxc(handle, 1, uv_signal_t, uv_handle_t); break;
        default:
            croak("Invalid handle type supplied");
    }
    if (NULL == handle) {
        croak("Cannot allocate space for a new UV::Handle object");
    }
    data_ptr->self = sv_bless(
        newRV_noinc(newSViv(PTR2IV(handle))),
        gv_stashpv(handle_namespace(type), GV_ADD)
    );

    /* add some data to our new handle */
    handle->data = (void *)data_ptr;
    return handle;
}

static void handle_on(uv_handle_t *handle, const char *name, SV *cb)
{
    SV *callback = NULL;
    handle_data_t *data_ptr = uv_data(handle);
    if (!data_ptr) return;

    callback = cb ? s_get_cv_croak(cb) : NULL;

    /* find out which callback to set */
    if (strEQ(name, "alloc")) {
        /* clear the callback's current value first */
        if (NULL != data_ptr->alloc_cb) {
            SvREFCNT_dec(data_ptr->alloc_cb);
            data_ptr->alloc_cb = NULL;
        }
        /* set the CB */
        if (NULL != callback) {
            data_ptr->alloc_cb = SvREFCNT_inc(callback);
        }
    }
    else if (strEQ(name, "check")) {
        /* clear the callback's current value first */
        if (NULL != data_ptr->check_cb) {
            SvREFCNT_dec(data_ptr->check_cb);
            data_ptr->check_cb = NULL;
        }
        /* set the CB */
        if (NULL != callback) {
            data_ptr->check_cb = SvREFCNT_inc(callback);
        }
    }
    else if (strEQ(name, "close")) {
        /* clear the callback's current value first */
        if (NULL != data_ptr->close_cb) {
            SvREFCNT_dec(data_ptr->close_cb);
            data_ptr->close_cb = NULL;
        }
        /* set the CB */
        if (NULL != callback) {
            data_ptr->close_cb = SvREFCNT_inc(callback);
        }
    }
    else if (strEQ(name, "idle")) {
        /* clear the callback's current value first */
        if (NULL != data_ptr->idle_cb) {
            SvREFCNT_dec(data_ptr->idle_cb);
            data_ptr->idle_cb = NULL;
        }
        /* set the CB */
        if (NULL != callback) {
            data_ptr->idle_cb = SvREFCNT_inc(callback);
        }
    }
    else if (strEQ(name, "poll")) {
        /* clear the callback's current value first */
        if (NULL != data_ptr->poll_cb) {
            SvREFCNT_dec(data_ptr->poll_cb);
            data_ptr->poll_cb = NULL;
        }
        /* set the CB */
        if (NULL != callback) {
            data_ptr->poll_cb = SvREFCNT_inc(callback);
        }
    }
    else if (strEQ(name, "prepare")) {
        /* clear the callback's current value first */
        if (NULL != data_ptr->prepare_cb) {
            SvREFCNT_dec(data_ptr->prepare_cb);
            data_ptr->prepare_cb = NULL;
        }
        /* set the CB */
        if (NULL != callback) {
            data_ptr->prepare_cb = SvREFCNT_inc(callback);
        }
    }
    else if (strEQ(name, "timer")) {
        /* clear the callback's current value first */
        if (NULL != data_ptr->timer_cb) {
            SvREFCNT_dec(data_ptr->timer_cb);
            data_ptr->timer_cb = NULL;
        }
        /* set the CB */
        if (NULL != callback) {
            data_ptr->timer_cb = SvREFCNT_inc(callback);
        }
    }
    else {
        croak("Invalid event name (%s)", name);
    }
}

/* HANDLE callbacks */
static void handle_alloc_cb(uv_handle_t* handle, size_t suggested_size, uv_buf_t* buf)
{
    handle_data_t *data_ptr = uv_data(handle);
    buf->base = malloc(suggested_size);
    buf->len = suggested_size;

    /* nothing else to do if we don't have a callback to call */
    if (NULL == data_ptr || NULL == data_ptr->alloc_cb) return;

    /* provide info to the caller: invocant, suggested_size */
    dSP;
    ENTER;
    SAVETMPS;

    PUSHMARK (SP);
    EXTEND (SP, 2);
    mPUSHs(newSVsv(uv_self(handle))); /* invocant */
    mPUSHi(suggested_size);

    PUTBACK;
    call_sv (data_ptr->alloc_cb, G_VOID);
    SPAGAIN;

    FREETMPS;
    LEAVE;
}

static void handle_check_cb(uv_check_t* handle)
{
    handle_data_t *data_ptr = uv_data(handle);

    /* call the close_cb if we have one */
    if (NULL == data_ptr || NULL == data_ptr->check_cb) return;

    /* provide info to the caller: invocant */
    dSP;
    ENTER;
    SAVETMPS;

    PUSHMARK (SP);
    EXTEND (SP, 1);
    mPUSHs(newSVsv(uv_self(handle))); /* invocant */

    PUTBACK;
    call_sv (data_ptr->check_cb, G_VOID);
    SPAGAIN;

    FREETMPS;
    LEAVE;
}

static void handle_close_cb(uv_handle_t* handle)
{
    handle_data_t *data_ptr = uv_data(handle);

    /* call the close_cb if we have one */
    if (NULL == data_ptr || NULL == data_ptr->close_cb) return;

    /* provide info to the caller: invocant */
    dSP;
    ENTER;
    SAVETMPS;

    PUSHMARK (SP);
    EXTEND (SP, 1);
    mPUSHs(newSVsv(uv_self(handle))); /* invocant */

    PUTBACK;
    call_sv (data_ptr->close_cb, G_VOID);
    SPAGAIN;

    FREETMPS;
    LEAVE;
}

static void handle_idle_cb(uv_idle_t* handle)
{
    handle_data_t *data_ptr = uv_data(handle);
    /* nothing else to do if we don't have a callback to call */
    if (NULL == data_ptr || NULL == data_ptr->idle_cb) return;

    /* provide info to the caller: invocant */
    dSP;
    ENTER;
    SAVETMPS;

    PUSHMARK (SP);
    EXTEND (SP, 1);
    mPUSHs(newSVsv(uv_self(handle))); /* invocant */

    PUTBACK;
    call_sv (data_ptr->idle_cb, G_VOID);
    SPAGAIN;

    FREETMPS;
    LEAVE;
}

static void handle_poll_cb(uv_poll_t* handle, int status, int events)
{
    handle_data_t *data_ptr = uv_data(handle);

    /* nothing else to do if we don't have a callback to call */
    if (NULL == data_ptr || NULL == data_ptr->poll_cb) return;

    /* provide info to the caller: invocant, status, events */
    dSP;
    ENTER;
    SAVETMPS;

    PUSHMARK (SP);
    EXTEND (SP, 3);
    mPUSHs(newSVsv(uv_self(handle))); /* invocant */
    mPUSHi(status);
    mPUSHi(events);

    PUTBACK;
    call_sv (data_ptr->poll_cb, G_VOID);
    SPAGAIN;

    FREETMPS;
    LEAVE;
}

static void handle_prepare_cb(uv_prepare_t* handle)
{
    handle_data_t *data_ptr = uv_data(handle);
    /* nothing else to do if we don't have a callback to call */
    if (NULL == data_ptr || NULL == data_ptr->prepare_cb) return;

    /* provide info to the caller: invocant */
    dSP;
    ENTER;
    SAVETMPS;

    PUSHMARK (SP);
    EXTEND (SP, 1);
    mPUSHs(newSVsv(uv_self(handle))); /* invocant */

    PUTBACK;
    call_sv (data_ptr->prepare_cb, G_VOID);
    SPAGAIN;

    FREETMPS;
    LEAVE;
}

static void handle_timer_cb(uv_timer_t* handle)
{
    handle_data_t *data_ptr = uv_data(handle);
    /* nothing else to do if we don't have a callback to call */
    if (NULL == data_ptr || NULL == data_ptr->timer_cb) return;

    /* provide info to the caller: invocant */
    dSP;
    ENTER;
    SAVETMPS;

    PUSHMARK (SP);
    EXTEND (SP, 1);
    mPUSHs(newSVsv(uv_self(handle))); /* invocant */

    PUTBACK;
    call_sv (data_ptr->timer_cb, G_VOID);
    SPAGAIN;

    FREETMPS;
    LEAVE;
}


MODULE = UV             PACKAGE = UV            PREFIX = uv_

PROTOTYPES: ENABLE

BOOT:
{
    PERL_MATH_INT64_LOAD_OR_CROAK;

    /* grab the PACKAGE hash. If it doesn't yet exist, create it */
    HV *stash = gv_stashpv("UV", GV_ADD);

    /* add some constants to the package stash */
    {
        /* expose the VERSION macros */
        newCONSTSUB(stash, "UV_VERSION_MAJOR", newSViv(UV_VERSION_MAJOR));
        newCONSTSUB(stash, "UV_VERSION_MINOR", newSViv(UV_VERSION_MINOR));
        newCONSTSUB(stash, "UV_VERSION_PATCH", newSViv(UV_VERSION_PATCH));
        newCONSTSUB(stash, "UV_VERSION_IS_RELEASE", newSViv(UV_VERSION_IS_RELEASE));
        newCONSTSUB(stash, "UV_VERSION_SUFFIX", newSVpvf("%s", UV_VERSION_SUFFIX));
        newCONSTSUB(stash, "UV_VERSION_HEX", newSViv(UV_VERSION_HEX));

        /* expose the different error constants */
        newCONSTSUB(stash, "UV_E2BIG", newSViv(UV_E2BIG));
        newCONSTSUB(stash, "UV_EACCES", newSViv(UV_EACCES));
        newCONSTSUB(stash, "UV_EADDRINUSE", newSViv(UV_EADDRINUSE));
        newCONSTSUB(stash, "UV_EADDRNOTAVAIL", newSViv(UV_EADDRNOTAVAIL));
        newCONSTSUB(stash, "UV_EAFNOSUPPORT", newSViv(UV_EAFNOSUPPORT));
        newCONSTSUB(stash, "UV_EAGAIN", newSViv(UV_EAGAIN));
        newCONSTSUB(stash, "UV_EAI_ADDRFAMILY", newSViv(UV_EAI_ADDRFAMILY));
        newCONSTSUB(stash, "UV_EAI_AGAIN", newSViv(UV_EAI_AGAIN));
        newCONSTSUB(stash, "UV_EAI_BADFLAGS", newSViv(UV_EAI_BADFLAGS));
        newCONSTSUB(stash, "UV_EAI_BADHINTS", newSViv(UV_EAI_BADHINTS));
        newCONSTSUB(stash, "UV_EAI_CANCELED", newSViv(UV_EAI_CANCELED));
        newCONSTSUB(stash, "UV_EAI_FAIL", newSViv(UV_EAI_FAIL));
        newCONSTSUB(stash, "UV_EAI_FAMILY", newSViv(UV_EAI_FAMILY));
        newCONSTSUB(stash, "UV_EAI_MEMORY", newSViv(UV_EAI_MEMORY));
        newCONSTSUB(stash, "UV_EAI_NODATA", newSViv(UV_EAI_NODATA));
        newCONSTSUB(stash, "UV_EAI_NONAME", newSViv(UV_EAI_NONAME));
        newCONSTSUB(stash, "UV_EAI_OVERFLOW", newSViv(UV_EAI_OVERFLOW));
        newCONSTSUB(stash, "UV_EAI_PROTOCOL", newSViv(UV_EAI_PROTOCOL));
        newCONSTSUB(stash, "UV_EAI_SERVICE", newSViv(UV_EAI_SERVICE));
        newCONSTSUB(stash, "UV_EAI_SOCKTYPE", newSViv(UV_EAI_SOCKTYPE));
        newCONSTSUB(stash, "UV_EALREADY", newSViv(UV_EALREADY));
        newCONSTSUB(stash, "UV_EBADF", newSViv(UV_EBADF));
        newCONSTSUB(stash, "UV_EBUSY", newSViv(UV_EBUSY));
        newCONSTSUB(stash, "UV_ECANCELED", newSViv(UV_ECANCELED));
        newCONSTSUB(stash, "UV_ECHARSET", newSViv(UV_ECHARSET));
        newCONSTSUB(stash, "UV_ECONNABORTED", newSViv(UV_ECONNABORTED));
        newCONSTSUB(stash, "UV_ECONNREFUSED", newSViv(UV_ECONNREFUSED));
        newCONSTSUB(stash, "UV_ECONNRESET", newSViv(UV_ECONNRESET));
        newCONSTSUB(stash, "UV_EDESTADDRREQ", newSViv(UV_EDESTADDRREQ));
        newCONSTSUB(stash, "UV_EEXIST", newSViv(UV_EEXIST));
        newCONSTSUB(stash, "UV_EFAULT", newSViv(UV_EFAULT));
        newCONSTSUB(stash, "UV_EFBIG", newSViv(UV_EFBIG));
        newCONSTSUB(stash, "UV_EHOSTUNREACH", newSViv(UV_EHOSTUNREACH));
        newCONSTSUB(stash, "UV_EINTR", newSViv(UV_EINTR));
        newCONSTSUB(stash, "UV_EINVAL", newSViv(UV_EINVAL));
        newCONSTSUB(stash, "UV_EIO", newSViv(UV_EIO));
        newCONSTSUB(stash, "UV_EISCONN", newSViv(UV_EISCONN));
        newCONSTSUB(stash, "UV_EISDIR", newSViv(UV_EISDIR));
        newCONSTSUB(stash, "UV_ELOOP", newSViv(UV_ELOOP));
        newCONSTSUB(stash, "UV_EMFILE", newSViv(UV_EMFILE));
        newCONSTSUB(stash, "UV_EMSGSIZE", newSViv(UV_EMSGSIZE));
        newCONSTSUB(stash, "UV_ENAMETOOLONG", newSViv(UV_ENAMETOOLONG));
        newCONSTSUB(stash, "UV_ENETDOWN", newSViv(UV_ENETDOWN));
        newCONSTSUB(stash, "UV_ENETUNREACH", newSViv(UV_ENETUNREACH));
        newCONSTSUB(stash, "UV_ENFILE", newSViv(UV_ENFILE));
        newCONSTSUB(stash, "UV_ENOBUFS", newSViv(UV_ENOBUFS));
        newCONSTSUB(stash, "UV_ENODEV", newSViv(UV_ENODEV));
        newCONSTSUB(stash, "UV_ENOENT", newSViv(UV_ENOENT));
        newCONSTSUB(stash, "UV_ENOMEM", newSViv(UV_ENOMEM));
        newCONSTSUB(stash, "UV_ENONET", newSViv(UV_ENONET));
        newCONSTSUB(stash, "UV_ENOPROTOOPT", newSViv(UV_ENOPROTOOPT));
        newCONSTSUB(stash, "UV_ENOSPC", newSViv(UV_ENOSPC));
        newCONSTSUB(stash, "UV_ENOSYS", newSViv(UV_ENOSYS));
        newCONSTSUB(stash, "UV_ENOTCONN", newSViv(UV_ENOTCONN));
        newCONSTSUB(stash, "UV_ENOTDIR", newSViv(UV_ENOTDIR));
        newCONSTSUB(stash, "UV_ENOTEMPTY", newSViv(UV_ENOTEMPTY));
        newCONSTSUB(stash, "UV_ENOTSOCK", newSViv(UV_ENOTSOCK));
        newCONSTSUB(stash, "UV_ENOTSUP", newSViv(UV_ENOTSUP));
        newCONSTSUB(stash, "UV_EPERM", newSViv(UV_EPERM));
        newCONSTSUB(stash, "UV_EPIPE", newSViv(UV_EPIPE));
        newCONSTSUB(stash, "UV_EPROTO", newSViv(UV_EPROTO));
        newCONSTSUB(stash, "UV_EPROTONOSUPPORT", newSViv(UV_EPROTONOSUPPORT));
        newCONSTSUB(stash, "UV_EPROTOTYPE", newSViv(UV_EPROTOTYPE));
        newCONSTSUB(stash, "UV_ERANGE", newSViv(UV_ERANGE));
        newCONSTSUB(stash, "UV_EROFS", newSViv(UV_EROFS));
        newCONSTSUB(stash, "UV_ESHUTDOWN", newSViv(UV_ESHUTDOWN));
        newCONSTSUB(stash, "UV_ESPIPE", newSViv(UV_ESPIPE));
        newCONSTSUB(stash, "UV_ESRCH", newSViv(UV_ESRCH));
        newCONSTSUB(stash, "UV_ETIMEDOUT", newSViv(UV_ETIMEDOUT));
        newCONSTSUB(stash, "UV_ETXTBSY", newSViv(UV_ETXTBSY));
        newCONSTSUB(stash, "UV_EXDEV", newSViv(UV_EXDEV));
        newCONSTSUB(stash, "UV_UNKNOWN", newSViv(UV_UNKNOWN));
        newCONSTSUB(stash, "UV_EOF", newSViv(UV_EOF));
        newCONSTSUB(stash, "UV_ENXIO", newSViv(UV_ENXIO));
        newCONSTSUB(stash, "UV_EMLINK", newSViv(UV_EMLINK));
    }
}

const char* uv_err_name(int err)

uint64_t uv_hrtime()

const char* uv_strerror(int err)

unsigned int uv_version()

const char* uv_version_string()


MODULE = UV             PACKAGE = UV::Handle      PREFIX = uv_handle_

PROTOTYPES: ENABLE

BOOT:
{
    /* grab the PACKAGE hash. If it doesn't yet exist, create it */
    HV *stash = gv_stashpv("UV::Handle", GV_ADD);

    /* add some constants to the package stash */

    /* expose the different handle type constants */
    newCONSTSUB(stash, "UV_ASYNC", newSViv(UV_ASYNC));
    newCONSTSUB(stash, "UV_CHECK", newSViv(UV_CHECK));
    newCONSTSUB(stash, "UV_FS_EVENT", newSViv(UV_FS_EVENT));
    newCONSTSUB(stash, "UV_FS_POLL", newSViv(UV_FS_POLL));
    newCONSTSUB(stash, "UV_IDLE", newSViv(UV_IDLE));
    newCONSTSUB(stash, "UV_NAMED_PIPE", newSViv(UV_NAMED_PIPE));
    newCONSTSUB(stash, "UV_POLL", newSViv(UV_POLL));
    newCONSTSUB(stash, "UV_PREPARE", newSViv(UV_PREPARE));
    newCONSTSUB(stash, "UV_PROCESS", newSViv(UV_PROCESS));
    newCONSTSUB(stash, "UV_STREAM", newSViv(UV_STREAM));
    newCONSTSUB(stash, "UV_TCP", newSViv(UV_TCP));
    newCONSTSUB(stash, "UV_TIMER", newSViv(UV_TIMER));
    newCONSTSUB(stash, "UV_TTY", newSViv(UV_TTY));
    newCONSTSUB(stash, "UV_UDP", newSViv(UV_UDP));
    newCONSTSUB(stash, "UV_SIGNAL", newSViv(UV_SIGNAL));
    newCONSTSUB(stash, "UV_FILE", newSViv(UV_FILE));
}

void DESTROY(UV::Handle handle)
    CODE:
    handle_destroy(handle);

SV * uv_handle__get_data(UV::Handle handle)
    CODE:
        handle_data_t *data_ptr = uv_data(handle);
        RETVAL = data_ptr->user_data ? newSVsv(data_ptr->user_data) : &PL_sv_undef;
    OUTPUT:
    RETVAL

void uv_handle__set_data(UV::Handle handle, SV *new_val = NULL)
    CODE:
    handle_data_t *data_ptr = uv_data(handle);
    if (NULL != data_ptr->user_data) {
        SvREFCNT_dec(data_ptr->user_data);
        data_ptr->user_data = NULL;
    }

    if (NULL != new_val && new_val != &PL_sv_undef) {
        data_ptr->user_data = newSVsv(new_val);
    }

UV::Loop uv_handle_loop(UV::Handle handle)
    CODE:
    RETVAL = handle->loop;
    OUTPUT:
    RETVAL

int uv_handle_active (UV::Handle handle)
    ALIAS:
        UV::Handle::is_active = 1
    CODE:
        PERL_UNUSED_VAR(ix);
        RETVAL = uv_is_active(handle);
    OUTPUT:
    RETVAL

int uv_handle_closing(UV::Handle handle)
    ALIAS:
        UV::Handle::is_closing = 1
    CODE:
        PERL_UNUSED_VAR(ix);
        RETVAL = uv_is_closing(handle);
    OUTPUT:
    RETVAL

void uv_handle_close(UV::Handle handle, SV *cb=NULL)
    CODE:
    if (items > 1) {
        cb = cb == &PL_sv_undef ? NULL : cb;
        handle_on(handle, "close", cb);
    }
    uv_close(handle, handle_close_cb);

int uv_handle_has_ref(UV::Handle handle)
    CODE:
        RETVAL = uv_has_ref(handle);
    OUTPUT:
    RETVAL

void uv_handle_on(UV::Handle handle, const char *name, SV *cb=NULL)
    CODE:
    cb = cb == &PL_sv_undef ? NULL : cb;
    handle_on(handle, name, cb);

void uv_handle_ref(UV::Handle handle)
    CODE:
    uv_ref(handle);

int uv_handle_type(UV::Handle handle)
    CODE:
    RETVAL = handle->type;
    OUTPUT:
    RETVAL

void uv_handle_unref(UV::Handle handle)
    CODE:
    uv_unref(handle);



MODULE = UV             PACKAGE = UV::Check      PREFIX = uv_check_

PROTOTYPES: ENABLE

SV * uv_check_new(SV *class, UV::Loop loop = NULL)
    CODE:
    int res;
    uv_check_t *handle = (uv_check_t *)handle_new(UV_CHECK);
    PERL_UNUSED_VAR(class);
    if (NULL == loop) {
        loop = uv_default_loop();
        if (!loop) {
            croak("Error getting a new default loop");
        }
        loop->data = (void *)1;
    }

    res = uv_check_init(loop, handle);
    if (0 != res) {
        Safefree(handle);
        croak("Couldn't initialize check (%i): %s", res, uv_strerror(res));
    }
    RETVAL = sv_2mortal(newSVsv(uv_self(handle)));
    OUTPUT:
    RETVAL

void DESTROY(UV::Check handle)
    CODE:
    if (NULL != handle && 0 == uv_is_closing((uv_handle_t *)handle) && 0 == uv_is_active((uv_handle_t *)handle)) {
        uv_check_stop(handle);
        uv_close((uv_handle_t *)handle, handle_close_cb);
        handle_data_destroy(uv_data(handle));
    }

int uv_check_start(UV::Check handle, SV *cb=NULL)
    CODE:
        if (items > 1) {
            cb = cb == &PL_sv_undef ? NULL : cb;
            handle_on((uv_handle_t *)handle, "check", cb);
        }
        RETVAL = uv_check_start(handle, handle_check_cb);
    OUTPUT:
    RETVAL

int uv_check_stop(UV::Check handle)



MODULE = UV             PACKAGE = UV::Idle      PREFIX = uv_idle_

PROTOTYPES: ENABLE

SV * uv_idle_new(SV *class, UV::Loop loop = NULL)
    CODE:
    int res;
    uv_idle_t *handle = (uv_idle_t *)handle_new(UV_IDLE);
    PERL_UNUSED_VAR(class);
    if (NULL == loop) {
        loop = uv_default_loop();
        if (!loop) {
            croak("Error getting a new default loop");
        }
        loop->data = (void *)1;
    }

    res = uv_idle_init(loop, handle);
    if (0 != res) {
        Safefree(handle);
        croak("Couldn't initialize idle (%i): %s", res, uv_strerror(res));
    }

    RETVAL = sv_2mortal(newSVsv(uv_self(handle)));
    OUTPUT:
    RETVAL

void DESTROY(UV::Idle handle)
    CODE:
    if (NULL != handle && 0 == uv_is_closing((uv_handle_t *)handle) && 0 == uv_is_active((uv_handle_t *)handle)) {
        uv_idle_stop(handle);
        uv_close((uv_handle_t *)handle, handle_close_cb);
        handle_data_destroy(uv_data(handle));
    }

int uv_idle_start(UV::Idle handle, SV *cb=NULL)
    CODE:
        if (uv_is_closing((uv_handle_t *)handle)) {
            croak("You can't call start on a closed handle");
        }
        if (items > 1) {
            cb = cb == &PL_sv_undef ? NULL : cb;
            handle_on((uv_handle_t *)handle, "idle", cb);
        }
        RETVAL = uv_idle_start(handle, handle_idle_cb);
    OUTPUT:
    RETVAL

int uv_idle_stop(UV::Idle handle)



MODULE = UV             PACKAGE = UV::Poll      PREFIX = uv_poll_

PROTOTYPES: ENABLE

BOOT:
{
    HV *stash = gv_stashpvn("UV::Poll", 8, TRUE);
    /* Poll Event Types */
    newCONSTSUB(stash, "UV_READABLE", newSViv(UV_READABLE));
    newCONSTSUB(stash, "UV_WRITABLE", newSViv(UV_WRITABLE));
    newCONSTSUB(stash, "UV_DISCONNECT", newSViv(UV_DISCONNECT));
    newCONSTSUB(stash, "UV_PRIORITIZED", newSViv(UV_PRIORITIZED));
}

SV * uv_poll_new(SV *class, int fd, UV::Loop loop = NULL)
    CODE:
    int res;
    uv_poll_t *handle = (uv_poll_t *)handle_new(UV_POLL);
    PERL_UNUSED_VAR(class);
    if (NULL == loop) {
        loop = uv_default_loop();
        if (!loop) {
            croak("Error getting a new default loop");
        }
        loop->data = (void *)1;
    }

    res = uv_poll_init(loop, handle, fd);
    if (0 != res) {
        Safefree(handle);
        croak("Couldn't initialize handle (%i): %s", res, uv_strerror(res));
    }

    RETVAL = sv_2mortal(newSVsv(uv_self(handle)));
    OUTPUT:
    RETVAL

SV * uv_poll_new_socket(SV *class, int fd, UV::Loop loop = NULL)
    CODE:
    int res;
    uv_poll_t *handle = (uv_poll_t *)handle_new(UV_POLL);
    PERL_UNUSED_VAR(class);
    if (NULL == loop) {
        loop = uv_default_loop();
        if (!loop) {
            croak("Error getting a new default loop");
        }
        loop->data = (void *)1;
    }

    res = uv_poll_init_socket(loop, handle, fd);
    if (0 != res) {
        Safefree(handle);
        croak("Couldn't initialize handle (%i): %s", res, uv_strerror(res));
    }

    RETVAL = sv_2mortal(newSVsv(uv_self(handle)));
    OUTPUT:
    RETVAL

void DESTROY(UV::Poll handle)
    CODE:
    if (NULL != handle && 0 == uv_is_closing((uv_handle_t *)handle) && 0 == uv_is_active((uv_handle_t *)handle)) {
        uv_poll_stop(handle);
        uv_close((uv_handle_t *)handle, handle_close_cb);
        handle_data_destroy(uv_data(handle));
    }

int uv_poll_start(UV::Poll handle, int events = UV_READABLE, SV *cb=NULL)
    CODE:
        if (uv_is_closing((uv_handle_t *)handle)) {
            croak("You can't call start on a closed handle");
        }
        if (items > 2) {
            cb = cb == &PL_sv_undef ? NULL : cb;
            handle_on((uv_handle_t *)handle, "poll", cb);
        }
        RETVAL = uv_poll_start(handle, events, handle_poll_cb);
    OUTPUT:
    RETVAL

int uv_poll_stop(UV::Poll handle)



MODULE = UV             PACKAGE = UV::Prepare      PREFIX = uv_prepare_

PROTOTYPES: ENABLE

SV * uv_prepare_new(SV *class, UV::Loop loop = NULL)
    CODE:
    int res;
    uv_prepare_t *handle = (uv_prepare_t *)handle_new(UV_PREPARE);
    PERL_UNUSED_VAR(class);
    if (NULL == loop) {
        loop = uv_default_loop();
        if (!loop) {
            croak("Error getting a new default loop");
        }
        loop->data = (void *)1;
    }

    res = uv_prepare_init(loop, handle);
    if (0 != res) {
        Safefree(handle);
        croak("Couldn't initialize prepare (%i): %s", res, uv_strerror(res));
    }

    RETVAL = sv_2mortal(newSVsv(uv_self(handle)));
    OUTPUT:
    RETVAL

void DESTROY(UV::Prepare handle)
    CODE:
    if (NULL != handle && 0 == uv_is_closing((uv_handle_t *)handle) && 0 == uv_is_active((uv_handle_t *)handle)) {
        uv_prepare_stop(handle);
        uv_close((uv_handle_t *)handle, handle_close_cb);
        handle_data_destroy(uv_data(handle));
    }

int uv_prepare_start(UV::Prepare handle, SV *cb=NULL)
    CODE:
        if (uv_is_closing((uv_handle_t *)handle)) {
            croak("You can't call start on a closed handle");
        }
        if (items > 1) {
            cb = cb == &PL_sv_undef ? NULL : cb;
            handle_on((uv_handle_t *)handle, "prepare", cb);
        }
        RETVAL = uv_prepare_start(handle, handle_prepare_cb);
    OUTPUT:
    RETVAL

int uv_prepare_stop(UV::Prepare handle)



MODULE = UV             PACKAGE = UV::Timer      PREFIX = uv_timer_

PROTOTYPES: ENABLE

SV * uv_timer_new(SV *class, UV::Loop loop = NULL)
    CODE:
    int res;
    uv_timer_t *handle = (uv_timer_t *)handle_new(UV_TIMER);
    PERL_UNUSED_VAR(class);
    if (NULL == loop) {
        loop = uv_default_loop();
        if (!loop) {
            croak("Error getting a new default loop");
        }
        loop->data = (void *)1;
    }

    res = uv_timer_init(loop, handle);
    if (0 != res) {
        Safefree(handle);
        croak("Couldn't initialize timer (%i): %s", res, uv_strerror(res));
    }

    RETVAL = sv_2mortal(newSVsv(uv_self(handle)));
    OUTPUT:
    RETVAL

void DESTROY(UV::Timer handle)
    CODE:
    if (NULL != handle && 0 == uv_is_closing((uv_handle_t *)handle) && 0 == uv_is_active((uv_handle_t *)handle)) {
        uv_timer_stop(handle);
        uv_close((uv_handle_t *)handle, handle_close_cb);
        handle_data_destroy(uv_data(handle));
    }

int uv_timer_again(UV::Timer handle)

int uv_timer_start(UV::Timer handle, uint64_t start=0, uint64_t repeat=0, SV *cb=NULL)
    CODE:
        if (uv_is_closing((uv_handle_t *)handle)) {
            croak("You can't call start on a closed handle");
        }
        if (items > 3) {
            cb = cb == &PL_sv_undef ? NULL : cb;
            handle_on((uv_handle_t *)handle, "timer", cb);
        }
        RETVAL = uv_timer_start(handle, handle_timer_cb, start, repeat);
    OUTPUT:
    RETVAL

int uv_timer_stop(UV::Timer handle)
    CODE:
        RETVAL = uv_timer_stop(handle);
    OUTPUT:
    RETVAL

uint64_t uv_timer_get_repeat(UV::Timer handle)
    CODE:
        RETVAL = uv_timer_get_repeat(handle);
    OUTPUT:
    RETVAL

void uv_timer_set_repeat(UV::Timer handle, uint64_t repeat)


MODULE = UV             PACKAGE = UV::Loop      PREFIX = uv_

PROTOTYPES: ENABLE

BOOT:
{
    HV *stash = gv_stashpvn("UV::Loop", 8, TRUE);
    /* Loop run constants */
    newCONSTSUB(stash, "UV_RUN_DEFAULT", newSViv(UV_RUN_DEFAULT));
    newCONSTSUB(stash, "UV_RUN_ONCE", newSViv(UV_RUN_ONCE));
    newCONSTSUB(stash, "UV_RUN_NOWAIT", newSViv(UV_RUN_NOWAIT));
    /* expose the Loop configure constants */
    newCONSTSUB(stash, "UV_LOOP_BLOCK_SIGNAL", newSViv(UV_LOOP_BLOCK_SIGNAL));
    newCONSTSUB(stash, "SIGPROF", newSViv(SIGPROF));
}

UV::Loop new (SV *class, int want_default = 0)
    ALIAS:
        UV::Loop::default_loop = 1
        UV::Loop::default = 2
    CODE:
    int ret;
    uv_loop_t * loop;
    PERL_UNUSED_VAR(class);
    if (ix == 1 || ix == 2) want_default = 1;
    if (0 == want_default) {
        Newx(loop, 1, uv_loop_t);
        if (NULL == loop) {
            croak("Unable to allocate space for a new loop");
        }
        ret = uv_loop_init(loop);
        if (0 != ret) {
            Safefree(loop);
            croak("Error initializing loop (%i): %s", ret, uv_strerror(ret));
        }
        RETVAL = loop;
    }
    else {
        loop = uv_default_loop();
        if (!loop) {
            croak("Error getting a new default loop");
        }
        loop->data = (void *)1;
        RETVAL = loop;
    }
    OUTPUT:
    RETVAL

void DESTROY (UV::Loop loop)
    CODE:
    /* 1. the default loop shouldn't be freed by destroying it's perl loop object */
    /* 2. not doing so helps avoid many global destruction bugs in perl, too */
    if (loop->data) {
        if (PL_dirty) {
            uv_loop_close(loop);
        }
    }
    else {
        if (0 == uv_loop_close(loop)) {
            Safefree(loop);
        }
    }

int uv_backend_fd(UV::Loop loop)

int uv_backend_timeout(UV::Loop loop)

int uv_close(UV::Loop loop)
    CODE:
        RETVAL = uv_loop_close(loop);
    OUTPUT:
    RETVAL

int uv_alive(UV::Loop loop)
    CODE:
    RETVAL = uv_loop_alive(loop);
    OUTPUT:
    RETVAL

int uv_loop_alive(UV::Loop loop)

int uv_configure(UV::Loop loop, uv_loop_option option, int value)
    CODE:
    RETVAL = uv_loop_configure(loop, option, value);
    OUTPUT:
    RETVAL

int uv_loop_configure(UV::Loop loop, uv_loop_option option, int value)

uint64_t uv_now(UV::Loop loop)

int uv_run(UV::Loop loop, uv_run_mode mode=UV_RUN_DEFAULT)

void uv_stop(UV::Loop loop)

void uv_update_time(UV::Loop loop)

void uv_walk(UV::Loop loop, SV *cb=NULL)
    CODE:
        cb = cb == &PL_sv_undef ? NULL : cb;
        uv_walk(loop, loop_walk_cb, (void *)cb);
