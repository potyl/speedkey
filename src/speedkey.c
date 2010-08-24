/* speed-key.c - Generate the WEP key of a SpeedTouch modem based on the SSID
 *               of the device.
 *
 * Copyright (C) 2010 Emmanuel Rodriguez <emmanuel.rodriguez@gmail.com>.
 *
 * This program is free software; you can redistribute it and/or modify it
 * under the terms of the GNU Lesser General Public License as published by the
 * Free Software Foundation; either version 2.1, or (at your option) any
 * later version.
 *
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.
 *
 * You should have received a copy of the GNU Lesser General Public License
 * along with this program; if not, write to the Free Software Foundation,
 * Inc., 51 Franklin Street, Fifth Floor, Boston, MA 02110-1301, USA.
 */

#define _GNU_SOURCE

#include <stdlib.h>
#include <string.h>
#include <stdio.h>
#include <ctype.h>
#include <pthread.h>
#include <getopt.h>
#include <time.h>

#ifdef HAS_OPENSSL
#    include <openssl/sha.h>
#    define  SHA1_BUFFER_TYPE(buffer) ((const unsigned char *) buffer)
#else
#    include "sha1.h"
#    define  SHA1_BUFFER_TYPE(buffer) ((const char *) buffer)
#endif

#include "config.h"

#define SERIAL_LENGTH 12
#define SHA1_DIGEST_BITS 160
#define SHA1_DIGEST_HEX_BYTES (SHA1_DIGEST_BITS / 4)
#define SHA1_DIGEST_BIN_BYTES (SHA1_DIGEST_BITS / 8)

/* Insert into the content of 'a' into buffer[pos] and 'b' into buffer[pos + 1] */
#define WRITE_BYTES(buffer, pos, a, b)  \
	do { \
		(buffer)[pos] = a; \
		(buffer)[(pos) + 1] = b; \
	} while (0)

/* Insert into buffer[pos] and buffer[pos+1] the value of sprintf("%02X, x) */
#define WRITE_HEX(buffer, pos, h)  WRITE_BYTES(buffer, pos, HEX[(h & 0xF0) >> 4], HEX[(h) & 0x0F])

/* Insert into buffer[pos] and buffer[pos+1] the value of sprintf("%02d", x) */
#define SERIAL_DIGIT(buffer, pos, x) WRITE_BYTES(buffer, pos, HEX[(x) / 10], HEX[(x) % 10])

/* Insert into buffer[pos] and buffer[pos+1] the value of a serial part */
#define SERIAL_PART(buffer, pos, x) \
	do { \
		if ((x) < 10) { \
			/* 0 -> "30", 1 -> "31", .., 9 -> "39" */ \
			WRITE_BYTES(buffer, pos, '3', HEX[x]); \
		} \
		else { \
			char c = HEX[x]; \
			WRITE_HEX(buffer, pos, c); \
		} \
	} while (0)

#define HEX_TO_BYTE(h) ((h) >= 'A' && (h) <= 'F' ? (h) - 'A' + 10 : (h) - '0')


struct _WifiRouter {
	char *hex_ssid;
	unsigned char *bin_ssid;
	size_t bin_ssid_len;
	size_t hex_ssid_len;
	const char *type;
};
typedef struct _WifiRouter WifiRouter;

struct _ThreadCtx {
	pthread_t tid;
	pthread_mutex_t *mutex;
	unsigned char batch_i;
	unsigned char batch_max;
	unsigned char year_start;
	unsigned char year_end;
	unsigned int debian_format;
	WifiRouter **routers;
	size_t max_ssid_len;
};
typedef struct _ThreadCtx ThreadCtx;


static void
compute_serials (ThreadCtx *ctx);

static void
process_serial (ThreadCtx *ctx, const char *serial, size_t len);

static void*
start_thread (void *data);

static int
sort_compare (const void *p1, const void *p2);

static WifiRouter**
parse_router_arg (int argc , char * const argv[]);

/*
   The mappings to use for converting a nibble to a hex string. This mapping
   extends to the whole alphabet because the generation of the serial numbers
   uses all letters.
*/
static char HEX [] = "0123456789ABCDEFGHIJKLMNOPQRSTUVWXYZ";


int
main (int argc , char * const argv[]) {
	int c;
	size_t i;
	size_t max_threads;
	ThreadCtx* threads;
	pthread_attr_t attr;
	pthread_mutex_t mutex;
	time_t clock;
	struct tm *now_tm;
	unsigned char year_start = 0;
	unsigned char year_end = 0;
	WifiRouter **routers = NULL;
	WifiRouter **routers_iter;
	size_t max_ssid_len = 0;

	struct option longopts[] = {
		{ "year-start", required_argument, NULL, 's' },
		{ "year-end",   required_argument, NULL, 'e' },
		{ "threads",    required_argument, NULL, 't' },
		{ "debian",     no_argument,       NULL, 'd' },
		{ "help",       no_argument,       NULL, 'h' },
		{ "version",    no_argument,       NULL, 'v' },
		{ NULL, 0, NULL, 0 },
	};

	unsigned short int debian_format = 0;
	max_threads = 1;
	while ( (c = getopt_long(argc, argv, "hvdt:s:e:", longopts, NULL)) != -1 ) {
		switch (c) {
			case 't':
				max_threads = (size_t) atoi(optarg);
			break;

			case 's':
				year_start = (size_t) atoi(optarg);
			break;

			case 'e':
				year_end = (size_t) atoi(optarg) + 1;
			break;

			case 'd':
				debian_format = 1;
			break;

			case 'h':
				printf("Usage: [OPTION]... SSID\n");
				printf("Where OPTION is one of:\n");
				printf("   --version,      -v     show the program's version\n");
				printf("   --help,         -h     print this help message\n");
				printf("   --debian,       -d     generate debian's /etc/network/interfaces format\n");
				printf("   --year-start Y, -s Y   generate serials starting at the given year\n");
				printf("   --year-end   Y, -e Y   generate serials up to the given year\n");
				printf("   --threads    T, -t T   number of threads to use\n");
				return 1;
			break;

			case 'v':
				printf("%s version %s\n", PACKAGE_NAME, PACKAGE_VERSION);
				return 0;
			break;
		}
	}
	argc -= optind;
	argv += optind;

	routers = parse_router_arg(argc, argv);
	if (routers == NULL) {
		printf("Usage: SSID...\n");
		return 1;
	}

	/* Get the legnth of the biggest SSID to parse */
	for (routers_iter = routers; *routers_iter != NULL; ++routers_iter) {
		WifiRouter *router = *routers_iter;
		if (max_ssid_len < router->bin_ssid_len) {
			max_ssid_len = router->bin_ssid_len;
		}
	}

	/* Set the current year as the last year for the serial codes to generate */
	if (!year_end) {
		time(&clock);
		now_tm = localtime(&clock);
		year_end = (unsigned char) (now_tm->tm_year - 100);
	}
	if (!year_start) {
		year_start = 4;
	}

	if (max_threads > 1) {
		/* Divide the work in batches */
		threads = malloc(max_threads * sizeof(ThreadCtx));
		pthread_attr_init(&attr);
		pthread_attr_setdetachstate(&attr, PTHREAD_CREATE_JOINABLE);
		pthread_mutex_init(&mutex, NULL);

		/* Launch the threads */
		for (i = 0; i < max_threads; ++i) {
			ThreadCtx *ctx = &threads[i];
			ctx->batch_i = i;
			ctx->batch_max = max_threads;
			ctx->year_start = year_start;
			ctx->year_end = year_end;
			ctx->debian_format = debian_format;
			ctx->mutex = &mutex;
			ctx->routers = routers;
			ctx->max_ssid_len = max_ssid_len;
			pthread_create(&ctx->tid, &attr, start_thread, ctx);
		}

		/* Wait for the threads to finish */
		pthread_attr_destroy(&attr);
		for (i = 0; i < max_threads; ++i) {
			ThreadCtx *ctx = &threads[i];
			void *value = NULL;
			pthread_join(ctx->tid, &value);
		}
		pthread_mutex_destroy(&mutex);
		free(threads);
	}
	else {
		/* No threads */
		ThreadCtx ctx;
		ctx.batch_i = 0;
		ctx.batch_max = 1;
		ctx.year_start = year_start;
		ctx.year_end = year_end;
		ctx.debian_format = debian_format;
		ctx.mutex = NULL;
		ctx.routers = routers;
		ctx.max_ssid_len = max_ssid_len;
		compute_serials(&ctx);
	}

	/* Cleanup */
	for (routers_iter = routers; *routers_iter != NULL; ++routers_iter) {
		WifiRouter *router = *routers_iter;
		free(router->hex_ssid);
		free(router->bin_ssid);
		free(router);
	}
	free(routers);

	return 0;
}


/*
 * Start the work of a new thread.
 */
static void*
start_thread (void *data) {
	ThreadCtx *ctx = (ThreadCtx *) data;
	compute_serials(ctx);
	pthread_exit(NULL);
}


/*
 * Computes all serial numbers of a device. This is done through brute force as
 * there's no heuristic than can help.
 *
 * The serial number is assumed to be in the following format:
 *   CP$(YY)$(WW)--$(P1)$(P2)$(P3)  ex: CP0923H3FHE
 * Where:
 *   $(YY) is the year [04, 09]
 *   $(WW) is the week number [01, 52]
 *   $(P*) a single character in the range ['A' .. 'Z', '0' .. '9']
 *
 * This function can be called from different threads in order to parallelize
 * the computations and get the results faster. When called from multiple
 * threads, the batches are distributed among all workers based on the modulo
 * of the serial's year (year % batch_max == batch_i). This means than a user
 * should not start more threads than there are years to be computed. Otherwise
 * exceeding threads will not be able to cooperate on the computation.
 *
 */
static void
compute_serials (ThreadCtx *ctx) {
	unsigned char year, week, p1, p2, p3;

	/* Serial number that gets digested through SHA1; all serials numbers start
	   with "CP" */
	char serial [SERIAL_LENGTH + 1];
	memset(serial, 0, sizeof(serial));
	serial[0] = 'C';
	serial[1] = 'P';

	/* Build each part of the serial string and compute the key for each unique
	   serial number */
	for (year = ctx->year_start; year < ctx->year_end; ++year) {
		if (year % ctx->batch_max != (ctx->batch_i)) {
			continue;
		}
		SERIAL_DIGIT(serial, 2, year);

		for (week = 1; week <= 52; ++week) {
			SERIAL_DIGIT(serial, 4, week);

			/* The serial contains 3 letters that are in the range ['A' .. 'Z', '0' .. '9'] */
			for (p1 = 0; p1 < 36; ++p1) {
				SERIAL_PART(serial, 6, p1);

				for (p2 = 0; p2 < 36; ++p2) {
					SERIAL_PART(serial, 8, p2);

					for (p3 = 0; p3 < 36; ++p3) {
						SERIAL_PART(serial, 10, p3);
						process_serial(ctx, serial, sizeof(serial));
					}
				}
			}
		}
	}
}


/*
 * Handles a single serial number. This function takes the serial and computes
 * its SHA1. From that digest the SSID and the KEY can be derrived. If the SSID
 * matches the wanted SSID (from ctx->wanted_ssid) then the KEY will be printed.
 */
static void
process_serial (ThreadCtx *ctx, const char *serial, size_t len) {
	WifiRouter **routers_iter;
	char is_key_computed = 0;
	char key [11];

	/* Will hold the SHA1 in binary format */
	unsigned char sha1_bin [SHA1_DIGEST_BIN_BYTES];

	/* Now that the serial number is generated we can compute its corresponding
	   key which is derived from its SHA1. */
	SHA1(SHA1_BUFFER_TYPE(serial), len - 1, sha1_bin);

	for (routers_iter = ctx->routers; *routers_iter != NULL; ++routers_iter) {
		WifiRouter *router = *routers_iter;
		unsigned char *ssid_ptr;
		int cmp;

		/* The SSID is in the last bytes of the SHA1 when converted to hex */
		ssid_ptr = &sha1_bin[SHA1_DIGEST_BIN_BYTES - ctx->max_ssid_len];

		/* If this is the desired SSID then we compute the key */
		cmp = bcmp(ssid_ptr, router->bin_ssid, router->bin_ssid_len);
		if (cmp < 0) {
			/* The SSID is smaller than the first SSID to match, no need to continute */
			return;
		}
		else if (cmp) {
			/* No match, try the next router */
			continue;
		}

		/* The key is in the first 5 bytes of the SHA1 when converted to hex */
		if (! is_key_computed) {
			size_t i;
			size_t pos = 0;
			for (i = 0; i < 5; ++i) {
				unsigned char c = sha1_bin[i];
				WRITE_HEX(key, pos, c);
				pos += 2;
			}
			key[pos] = '\0';
			is_key_computed = 1;
		}

		if (ctx->mutex != NULL) pthread_mutex_lock(ctx->mutex);
		if (ctx->debian_format) {
			printf(
				"iface speedkey inet dhcp\n"
				"\twpa-ssid       %s%s\n"
				"\twpa-passphrase %s\n",
				router->type, router->hex_ssid,
				key
			);
		}
		else {
			printf("Matched SSID %s, key: %s, serial: %s\n", router->hex_ssid, key, serial);
		}
		if (ctx->mutex != NULL) pthread_mutex_unlock(ctx->mutex);
	}
}


static int
sort_compare (const void *p1, const void *p2) {
	return strcmp(
		*((const char **)p1),
		*((const char **)p2)
	);
}


static WifiRouter**
parse_router_arg (int argc , char * const argv[]) {

	WifiRouter **routers;
	int i;

	if (argc < 1) {
		return NULL;
	}

	routers = (WifiRouter **) malloc((argc + 1) * sizeof(WifiRouter *));
	if (routers == NULL) {
		return NULL;
	}
	routers[argc] = NULL;

	qsort((void *) argv, argc, sizeof argv[0], sort_compare);

	for (i = 0; i < argc; ++i) {
		const char *arg;
		WifiRouter *router;
		const char *ssid;
		size_t j;
		size_t offset = 0;

		arg = argv[i];
		routers[i] = router = (WifiRouter *) malloc(sizeof(WifiRouter));
		if (router == NULL) {
			return NULL;
		}

		/* Allow "SpeedTouch" at the beginning of arg (for lazy pasters like me) */
		router->type = "SpeedTouch";
		ssid = strcasestr(arg, router->type);
		if (ssid) {
			offset = strlen(router->type);
			ssid += offset;
		}

		if (ssid == NULL) {
			router->type = "Thomson";
			ssid = strcasestr(arg, router->type);
			if (ssid) {
				offset = strlen(router->type);
				ssid += offset;
			}
		}

		if (ssid == NULL) {
			ssid = arg;
			router->type = "SpeedTouch";
		}

		/* Make sure that the target SSID is in upper case */
		router->hex_ssid_len = strlen(ssid);
		router->bin_ssid_len = router->hex_ssid_len / 2;
		router->hex_ssid = malloc(router->hex_ssid_len + 1);
		router->bin_ssid = malloc(router->bin_ssid_len);

		for (j = 0; j < router->hex_ssid_len; ++j) {
			char c = toupper((unsigned char) ssid[j]);
			router->hex_ssid[j] = c;
			if ( !  ( (c >= '0' &&  c <= '9') || (c >= 'A' && c <= 'F') )  ) {
				printf("Invalid character '%c' at position %i in SSID %s\n", c, (int) (offset + j + 1), arg);
				exit(1);
			}
		}
		router->hex_ssid[router->hex_ssid_len] = '\0';

		/* Transform the SSIDs into binary, this will make for faster lookups */
		for (j = 0; j < router->bin_ssid_len; ++j) {
			size_t pos = j * 2;
			router->bin_ssid[j] =
				  (HEX_TO_BYTE(router->hex_ssid[pos]) << 4)
				| (HEX_TO_BYTE(router->hex_ssid[pos + 1]))
			;
		}
	}

	return routers;
}

