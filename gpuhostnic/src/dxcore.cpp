#include "headers.h"

int tx_core(void *args)
{
    GpuHostNicShmem *shm = (GpuHostNicShmem *)args;
    struct rte_gpu_comm_list *comm_list;
    struct pcap_packet_header packet_header;
    struct timeval ts;
    int ret = 0;
    bool cap;

    printf("[DX CORE] Starting...\n");
    cudaSetDevice(GPU_ID);

    while (keep_alive(shm))
    {
        while (keep_alive(shm) && shm->dxlist_isreadable(&ret) == false)
            if (ret != 0)
            {
                fprintf(stderr, "rte_gpu_comm_get_status error, killing the app...\n");
                GpuHostNicShmem::force_quit = true;
                return EXIT_FAILURE;
            }

        if (killed(shm) && shm->dxlist_isreadable(&ret) == false)
            break;

        comm_list = shm->dxlist_read();

        for (uint32_t i = 0; i < comm_list->num_pkts; i++)
        {
            cap = comm_list->pkt_list[i].size & 1;
            comm_list->pkt_list[i].size >>= 1;
            gettimeofday(&(ts), NULL);
            packet_header.ts_sec = ts.tv_sec;
            packet_header.ts_usec = ts.tv_usec;
            packet_header.caplen = cap ? MAX_HLEN : comm_list->pkt_list[i].size;
            packet_header.len = comm_list->pkt_list[i].size;
            fwrite_unlocked(&(packet_header), sizeof(pcap_packet_header), 1, shm->pcap_fp);
            fwrite_unlocked((const void*)comm_list->pkt_list[i].addr, packet_header.caplen, 1, shm->pcap_fp);
        }

        shm->dxlist_clean();
    }
    return EXIT_SUCCESS;
}