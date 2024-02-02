#ifndef __TYPES_H
#define __TYPES_H

/* Compatibility stuff */
#define _XOPEN_SOURCE 700 /* Required for signal handling */
typedef unsigned char u_char;
typedef unsigned int u_int;
typedef unsigned short u_short;
/* ------------------- */

#define OK 0
#define ERROR -1
#define MIN_LENGTH 42 /* Minimum length of supported headers: ETH + IP + UDP */
#define DISK_BLOCK 8192
#define BUFFERSIZE (DISK_BLOCK + MIN_LENGTH - 1) / MIN_LENGTH
#endif