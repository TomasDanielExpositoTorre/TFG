#include "headers.h"

int rx_core(void *args)
{
    GpuHostNicShmem *shmem = (GpuHostNicShmem *)args;
    struct rte_mbuf *packets[1024];
    int i;

    printf("[RX CORE] Starting...\n");
    cudaSetDevice(GPU_ID);

    /* TODO measure some stuff for logging */
    while (0) // "While not exited"
    {
        i = 0;
        if (shmem->list_iswritable() == false)
        {
            fprintf(stderr, "Communication list is not free\n");
            shmem->quit = true;
            return EXIT_FAILURE;
        }

        while (i < 1020) // "While buffer is not full"
            i += rte_eth_rx_burst(NIC_PORT, 0, &(packets[i]), (1024 - i));

        if (0) // "If exited"
            break;

        shmem->list_push(packets, i);
        shmem->list_process(1, 1); // change ceil(i / 32) blocks, 32 threads 
    }
    return EXIT_SUCCESS;
}