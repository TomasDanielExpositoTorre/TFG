#include "headers.h"

int tx_core(void *args)
{
    GpuHostNicShmem *shm = (GpuHostNicShmem *)args;
    int ret = 0;
    printf("[DX CORE] Starting...\n");

    cudaSetDevice(GPU_ID);

    while (not_quit(shm))
    {
        while (shm->list_isreadable(&ret) == false)
            if (ret)
            {
                fprintf(stderr, "rte_gpu_comm_get_status error, killing the app...\n");
                GpuHostNicShmem::force_quit = true;
                return EXIT_FAILURE;
            }
        // todo write in pcap format
        // for each packet:
        //  flag = size & 1
        //  size >> 1
        //  dump(caplen=flagged ? MAX_HLEN : size, len=size)
        // list.status = FREE
    }
    return EXIT_SUCCESS;
}