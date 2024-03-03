#ifndef SPC_MACROS_H
#define SPC_MACROS_H
#include "headers.h"

#define TRY(condition, error_msg) \
    if (condition)                \
    rte_exit(EXIT_FAILURE, error_msg)

#define VTRY(condition, error_msg, ...) \
    if (condition)                      \
    rte_exit(EXIT_FAILURE, error_msg, __VA_ARGS__)

#define KARGS_INIT(args)   \
    args->percentage = 40; \
    args->runlen = 15;     \
    args->ktype = VANILLA_PACKET_THREAD

#define RTE_LCORE_FOREACH_WORKER(i)        \
    for (i = rte_get_next_lcore(-1, 1, 0); \
         i < RTE_MAX_LCORE;                \
         i = rte_get_next_lcore(i, 1, 0))

#define RXQUEUES 1
#define TXQUEUES 1
#define NIC_PORT 0
#define GPU_ID 0                  /* Temporal macro */
#define RTE_PKTBUF_DATAROOM 2048U /* Temporal macro */
#define GPU_PAGE 65536U           /* Temporal macro */
#define ELEMS 8192U               /* Temporal macro */

#endif