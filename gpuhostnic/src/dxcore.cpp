#include "headers.h"

int tx_core(void *args)
{
    GpuHostNicShmem *shmem = (GpuHostNicShmem *)args;
    int ret = 0;
    printf("[TX Core] Starting...\n");
    cudaSetDevice(GPU_ID);

    /* TODO measure some stuff */
    while (0) // "While not quit"
    {
        while (shmem->list_isreadable(&ret) == false)
            if (ret)
            {
                fprintf(stderr, "rte_gpu_comm_get_status error, killing the app...\n");
                shmem->quit = true;
                return EXIT_FAILURE;
            }

        /* Write packets in .pcap format (pcapdump_t??)*/
        shmem->list_pop();
    }
    return EXIT_SUCCESS;
}