/*
 * libmtp_shims.c — the ONLY symbols the libptp2 subset (ptp.o + glue.o)
 * expects from libmtp.c/util.c/mtpz.c that we do not compile. Minimal
 * implementations, behavior-compatible for our prober's use:
 *
 *   LIBMTP_debug      — debug-hook indirection used by util.h's
 *                       LIBMTP_DEBUG macro (only active when the env var
 *                       LIBMTP_DEBUG is set; stderr then).
 *   data_dump_ascii   — util.c ascii dump helper (debug output only).
 *   device_unknown    — music-players.h table tail sentinel (libmtp.c).
 *   ptp_nikon_getptpipguid — mtpz.c stub (ptp.c calls it from
 *                       ptp_nikon_writewifiprofile; returns a constant).
 */
#include <stdio.h>
#include <stdarg.h>
#include <string.h>
#include "libmtp.h"

/* libmtp.h: extern int LIBMTP_debug — the debug level flag (util.h's
 * LIBMTP_DEBUG macro checks it; default off like libmtp) */
int LIBMTP_debug = 0;

/* util.c: data_dump_ascii — print len bytes as hex+ascii (debug only) */
void data_dump_ascii(FILE *f, const void *data, size_t len, size_t offset)
{
    const unsigned char *p = (const unsigned char *)data;
    size_t i, j;
    for (i = 0; i < len; i += 16) {
        fprintf(f, "%08zx  ", offset + i);
        for (j = 0; j < 16; j++) {
            if (i + j < len) fprintf(f, "%02x ", p[i + j]);
            else fprintf(f, "   ");
            if (j == 7) fprintf(f, " ");
        }
        fprintf(f, " |");
        for (j = 0; j < 16 && i + j < len; j++)
            fprintf(f, "%c", (p[i + j] >= 32 && p[i + j] < 127) ? p[i + j] : '.');
        fprintf(f, "|\n");
    }
}

/* libmtp.c: the unknown-device sentinel closing the music-players table */
LIBMTP_device_entry_t device_unknown =
    { "Unknown vendor", 0x0000, "Unknown product", 0x0000, 0x0000 };

/* mtpz.c: PTP/IP GUID generator stub (Nintendo target never calls the
 * real path; ptp.c references the symbol unconditionally) */
void ptp_nikon_getptpipguid(unsigned char *guid)
{
    static const unsigned char g[16] = {
        0x01, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
        0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00
    };
    memcpy(guid, g, 16);
}
