#include "headers.h"

int rx_core(void *args)
{
    GpuHostNicShmem *shm = (GpuHostNicShmem *)args;
    struct rte_mbuf *packets[1024];
    int i;

    printf("[RX CORE] Starting...\n");
    cudaSetDevice(GPU_ID);

    while (not_quit(shm))
    {
        i = 0;
        if (shm->list_iswritable() == false)
        {
            fprintf(stderr, "Communication list not free, quitting...\n");
            shm->self_quit = true;
            return EXIT_FAILURE;
        }

        while (i < 1016 && not_quit(shm))
            i += rte_eth_rx_burst(NIC_PORT, 0, &(packets[i]), (1024 - i));

        if (has_quit(shm))
            break;

        shm->list_push(packets, i);
        shm->list_process(CEIL(i, 32), 32);
    }
    return EXIT_SUCCESS;
}