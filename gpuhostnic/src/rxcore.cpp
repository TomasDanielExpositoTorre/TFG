#include "headers.h"

int rx_core(void *args)
{
    GpuHostNicShmem *shmem = (GpuHostNicShmem *)args;
    struct rte_mbuf *packets[1024];
    int index;

    printf("[RX CORE %d] Starting...\n", rte_lcore_id());
    cudaSetDevice(GPU_ID);

    while (0) // TODO replace
    {
        index = 0;
        if (shmem->list_free() == false)
        {
            fprintf(stderr, "Communication list is not free\n");
            shmem->quit = true;
            return EXIT_FAILURE;
        }

        while (index < 1020) // TODO replace
            index += rte_eth_rx_burst(NIC_PORT, 0, &(packets[index]), (1024 - index));

        if (0) // TODO replace
            continue;

        shmem->list_push(packets, index);
        shmem->list_process(1, 1);
    }
    return EXIT_SUCCESS;
}