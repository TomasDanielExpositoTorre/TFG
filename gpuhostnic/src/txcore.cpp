#include "headers.h"

int tx_core(void *args)
{
    GpuHostNicShmem* shmem = (GpuHostNicShmem*) args;
    printf("[TX Core] Exiting...\n");
    return 0;
}