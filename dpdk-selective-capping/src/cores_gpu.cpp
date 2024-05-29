#include "headers.h"

int gpu_rx(void *args)
{
    GpuCommunicationRing *shm = (GpuCommunicationRing *)args;
    int i;

    if (shm->args.gpu_workload == true)
        cudaSetDevice(GPU_ID);
    printf("[%cPU-RX %d] Starting...\n", shm->args.gpu_workload ? 'G' : 'C', shm->id);

    while (CommunicationRing::force_quit == false)
    {
        while (shm->rxlist_iswritable() == false)
            ;

        if ((i = shm->rxlist_write()) == 0)
            break;

        shm->rxlist_process(i);
    }
    shm->self_quit = true;
    return EXIT_SUCCESS;
}

int gpu_dx(void *args)
{
    GpuCommunicationRing *shm = (GpuCommunicationRing *)args;
    struct rte_mbuf **packets;
    struct pcap_packet_header *headers;
    int npkts;

    if (shm->args.gpu_workload == true)
        cudaSetDevice(GPU_ID);
    printf("[%cPU-DX %d] Starting...\n", shm->args.gpu_workload ? 'G' : 'C', shm->id);

    while (shm->self_quit == false || shm->dxlist_isempty() == false)
    {
        while (shm->dxlist_isreadable() == false && !(shm->self_quit == true && shm->dxlist_isempty()))
            ;

        if (shm->self_quit == true && shm->dxlist_isempty())
            break;

        packets = shm->dxlist_read(&headers, &npkts);

        shm->dxlog.lock();
        for (int i = 0; i < npkts; i++)
            shm->stats.stored_bytes += headers[i].caplen;
        shm->dxlog.unlock();

#ifndef SIM_STORAGE
        for (int i = 0; i < npkts; i++)
        {
            fwrite_unlocked(&headers[i], sizeof(pcap_packet_header), 1, shm->pcap_fp);
            fwrite_unlocked((const void *)packets[i]->buf_addr, headers[i].caplen, 1, shm->pcap_fp);
        }
#endif
        shm->dxlist_clean();
    }
    return EXIT_SUCCESS;
}
