#ifndef SPC_MACROS_H
#define SPC_MACROS_H

#include "headers.h"

/* =====================  Macro  Functions  ===================== */

/**
 * TODO document
 */
#define RTE_CHECK(cond, error_msg) \
    if (cond)                      \
    rte_exit(EXIT_FAILURE, error_msg)

/**
 * TODO document
 */
#define RTE_ERRCHECK(stmt, error_msg, ...) \
    ret = (stmt);                          \
    if (ret < 0)                           \
    rte_exit(EXIT_FAILURE, error_msg, __VA_ARGS__)

/**
 * TODO document
 */
#define RTE_WAIT_WORKERS(id, ret)                             \
    for (id = rte_get_next_lcore(-1, 1, 0);                   \
         id < RTE_MAX_LCORE && ret >= 0;                      \
         id = rte_get_next_lcore(id, 1, 0))                   \
    {                                                         \
        ret = rte_eal_wait_lcore(id);                         \
        if (rte_eal_wait_lcore(id) < 0)                       \
            fprintf(stderr, "bad exit for coreid: %d\n", id); \
    }

/* =====================  Temporal  Macros  ===================== */

#define RXQUEUES 1
#define TXQUEUES 1

#define NIC_PORT 0
#define GPU_ID 0

#define RTE_PKTBUF_DATAROOM 2048U
#define GPU_PAGE 65536U
#define ELEMS 8192U
#define BURST_ELEMS 4096U
#endif