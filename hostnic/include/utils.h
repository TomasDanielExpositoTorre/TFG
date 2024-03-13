#ifndef SPC_UTILS_H
#define SPC_UTILS_H

/* =====================  Compatibility Definitions  ===================== */

#define _XOPEN_SOURCE 700
typedef unsigned char u_char;
typedef unsigned int u_int;
typedef unsigned short u_short;

/* =====================     Capping Definitions     ===================== */
#define MIN_ASCII 0x20
#define MAX_ASCII 0x7E
#define NO_CAPPING 0
#define ERR_UNSUPPORTED -1
#define ERR_ILLFORMED -2

#define TO_MS_VAL 10
#define PCAP_BUFSIZE 8192

/* =====================      Extra Definitions      ===================== */
#define false 0
#define true 1

/* =====================       Function Macros       ===================== */

#define psem_init(x) pthread_mutex_init(&(x), NULL)
#define psem_destroy(x) pthread_mutex_destroy(&(x))
#define psem_down(x) pthread_mutex_lock(&(x))
#define psem_up(x) pthread_mutex_unlock(&(x))

#endif