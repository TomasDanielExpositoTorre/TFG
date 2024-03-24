#ifndef SPC_HEADERS_H
#define SPC_HEADERS_H

/* =====================  Standard Headers  ===================== */
#include <stdlib.h>
#include <argp.h>
#include <signal.h>
#include <sys/time.h>
#include <vector>
#include <mutex>

/* =====================    DPDK Headers    ===================== */
#include <rte_common.h>
#include <rte_log.h>
#include <rte_malloc.h>
#include <rte_memory.h>
#include <rte_memcpy.h>
#include <rte_eal.h>
#include <rte_launch.h>
#include <rte_atomic.h>
#include <rte_cycles.h>
#include <rte_prefetch.h>
#include <rte_lcore.h>
#include <rte_per_lcore.h>
#include <rte_branch_prediction.h>
#include <rte_interrupts.h>
#include <rte_random.h>
#include <rte_debug.h>
#include <rte_ether.h>
#include <rte_ethdev.h>
#include <rte_mempool.h>
#include <rte_mbuf.h>
#include <rte_metrics.h>
#include <rte_bitrate.h>
#include <rte_latencystats.h>
#include <rte_gpudev.h>

/* =====================    CUDA Headers    ===================== */
#include <cuda.h>
#include <cuda_runtime.h>
#include <cuda_runtime_api.h>
#include <cuda_profiler_api.h>

/* =====================    More Headers    ===================== */
#include "kernel.h"
#include "gpuhostnic_shmem.h"
#include "macros.h"
#include "utils.h"

#endif