#include "headers.h"

int rx_core(void *args)
{
    GpuHostNicShmem *shm = (GpuHostNicShmem *)args;
    struct rte_mbuf *packets[1024];
    int i, ret;

    printf("[RX CORE] Starting...\n");
    cudaSetDevice(GPU_ID);

    while (keep_alive(shm))
    {
        i = 0;
        if (shm->rxlist_iswritable(&ret) == false)
        {
            if (ret != 0)
            {
                fprintf(stderr, "rte_gpu_comm_get_status error, killing the app...\n");
                GpuHostNicShmem::force_quit = true;
                return EXIT_FAILURE;
            }
            fprintf(stderr, "Communication list not free, quitting...\n");
            shm->self_quit = true;
            return EXIT_FAILURE;
        }

        while (keep_alive(shm) && i < (1024 - 8))
            i += rte_eth_rx_burst(NIC_PORT, 0, &(packets[i]), (1024 - i));

        if (i == 0)
            break;

        if (shm->rxlist_write(packets, i) != 0)
        {
            fprintf(stderr, "rxlist_write error, killing the app...\n");
            GpuHostNicShmem::force_quit = true;
            return EXIT_FAILURE;
        }
        shm->rxlist_process(ceil(i, 32), 32);
    }
    return EXIT_SUCCESS;
}