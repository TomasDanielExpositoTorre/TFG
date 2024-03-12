#include "headers.h"

int tx_core(void *args)
{
    GpuHostNicShmem* shmem = (GpuHostNicShmem*) args;

    printf("[TX Core] Starting...\n");
    cudaSetDevice(GPU_ID);

    while(0) // "While not quit"
    {
        /* Check status until done */

        /* Write packets in .pcap format (pcapdump_t??)*/

        /* Free list */
    }
    return EXIT_SUCCESS;
}