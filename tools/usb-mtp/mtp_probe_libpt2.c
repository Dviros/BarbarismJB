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
    int open;
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
 * dev_open: mirror of LIBMTP_OpenDevice, INCLUDING libmtp's claim-retry
 * reality on macOS (icdd fights us): killall the trio and re-configure
 * until configure_usb_device succeeds. configure_usb_device re-finds the
 * device by bus/devnum internally, so each retry re-enumerates fresh.
 */
static int dev_open(Dev *d)
{
    libusb_context *ctx = NULL;
    uint8_t devnum = 0, busnum = 0;
    int attempt;

    memset(d, 0, sizeof(*d));
    if (libusb_init(&ctx) != LIBUSB_SUCCESS) {
        fprintf(stderr, "libusb_init failed\n");
        return -1;
    }

    for (attempt = 0; attempt < 8; attempt++) {
        void *usbinfo = NULL;
        LIBMTP_error_number_t err;
        PTPParams *p = &d->params;

        kill_imaging_trio();
        usleep(120000);
        /* grace window: post-reset re-enumeration can take ~1s */
        if (!find_console(ctx, &devnum, &busnum, attempt ? 2000 : 500)) {
            jr("stage\":\"dev_open\",\"detail\":\"device not enumerated\","
               "\"attempt\":%d", attempt);
            continue;
        }
        /* == LIBMTP_OpenDevice's PTPParams setup (libmtp.c:1955+) == */
        memset(p, 0, sizeof(*p));
        p->device_flags = 0;
        p->nrofobjects = 0;
        p->cachetime = 2;
        p->objects = NULL;
        p->response_packet_size = 0;
        p->response_packet = NULL;
        p->data = NULL;
        p->debug_func = NULL;
        p->error_func = NULL;
        p->byteorder = PTP_DL_LE;
        p->cd_locale_to_ucs2 = iconv_open("UTF-16LE", "UTF-8");
        p->cd_ucs2_to_locale = iconv_open("UTF-8", "UTF-16LE");
        if (p->cd_locale_to_ucs2 == (iconv_t)-1 ||
            p->cd_ucs2_to_locale == (iconv_t)-1) {
            fprintf(stderr, "iconv_open failed\n");
            return -1;
        }
        memset(&d->raw, 0, sizeof(d->raw));
        d->raw.device_entry.vendor = (char *)"Nintendo";
        d->raw.device_entry.vendor_id = VID;
        d->raw.device_entry.product = (char *)"Switch 2 capmtp";
        d->raw.device_entry.product_id = PID;
        d->raw.device_entry.device_flags = 0;
        d->raw.bus_location = busnum;
        d->raw.devnum = devnum;

        /* the REAL libmtp configure+opensession (tolerates
         * SessionAlreadyOpened; retries on IO error with usb reset) */
        err = configure_usb_device(&d->raw, p, &usbinfo);
        if (err == LIBMTP_ERROR_NONE && usbinfo) {
            d->ptp_usb = (PTP_USB *)usbinfo;
            d->ptp_usb->params = p;       /* libmtp.c does this right after */
            d->open = 1;
            jr("stage\":\"dev_open\",\"detail\":\"configure_usb_device ok\","
               "\"attempt\":%d,\"session_txid\":%u",
               attempt, (unsigned)p->transaction_id);
            return 0;
        }
        jr("stage\":\"dev_open\",\"detail\":\"configure failed\","
           "\"attempt\":%d,\"err\":%d", attempt, (int)err);
    }
    libusb_exit(ctx);
    fprintf(stderr, "dev_open: could not configure the device (Image "
            "Capture race? console in Copy-to-Computer mode?)\n");
    return -1;
}

static void dev_close(Dev *d)
{
    if (!d->open) return;
    close_device(d->ptp_usb, &d->params);   /* release + libusb_close */
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
            (void)xfer(d, "GetNumObjects", OC_GETNUMOBJECTS, 3,
                       (const uint32_t[]){sids.Storage[i], 0, 0}, 1);
            (void)xfer(d, "GetObjectHandles", OC_GETHANDLES, 3,
                       (const uint32_t[]){sids.Storage[i], 0, 0}, 1);
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
    printf("  %-48s %s\n", "corpus size (== mtp_probe.py)",
           n_probes == 14 ? "PASS" : "FAIL");
    ok &= (n_probes == 14);
    printf("  %-48s %s\n", "opcode values",
           (OC_GETTHUMB == 0x100a && OC_GETOBJECT == 0x1009 &&
            OC_GETHANDLES == 0x1007) ? "PASS" : "FAIL");
    ok &= (OC_GETTHUMB == 0x100a && OC_GETOBJECT == 0x1009 &&
           OC_GETHANDLES == 0x1007);
    printf("  %-48s %s\n", "probe names match python corpus",
           (strcmp(PROBES[0].name, "getobjectinfo_handle_zero") == 0 &&
            strcmp(PROBES[6].name, "getobject_partial_nodata") == 0 &&
            strcmp(PROBES[13].name, "closesession_untidy") == 0)
           ? "PASS" : "FAIL");
    ok &= (strcmp(PROBES[0].name, "getobjectinfo_handle_zero") == 0 &&
           strcmp(PROBES[6].name, "getobject_partial_nodata") == 0 &&
           strcmp(PROBES[13].name, "closesession_untidy") == 0);
    printf("mtp_probe_libpt2 self-test: %s\n", ok ? "PASS" : "FAIL");
    return ok ? 0 : 1;
}

static void usage(void)
{
    fprintf(stderr,
        "usage: mtp_probe_libpt2 --baseline | --probe NAME | --suite | "
        "--list | --self-test\n"
        "                    [--runs-dir DIR] [--wait SEC]\n");
}

int main(int argc, char **argv)
{
    const char *runs_dir = NULL, *probe_name = NULL;
    int do_baseline = 0, do_suite = 0, do_list = 0, do_self = 0, wait_s = 0;
    int i;
    char defdir[512];

    for (i = 1; i < argc; i++) {
        if (!strcmp(argv[i], "--baseline")) do_baseline = 1;
        else if (!strcmp(argv[i], "--suite")) do_suite = 1;
        else if (!strcmp(argv[i], "--list")) do_list = 1;
        else if (!strcmp(argv[i], "--self-test")) do_self = 1;
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
    if (!do_baseline && !do_suite && !probe_name) { usage(); return 2; }

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
