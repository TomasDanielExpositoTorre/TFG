#include "headers.h"

int gpu_rx(void *args)
{
    GpuCommunicationRing *ring = (GpuCommunicationRing *)args;
    enum rte_gpu_comm_list_status s = RTE_GPU_COMM_LIST_ERROR;
    struct timeval tv;
    int i, npkts, ret;

    cudaSetDevice(gpu);
    printf("[GPU-RX %d] Starting...\n", ring->id);

    while (ring->force_quit == false)
    {
        /* Wait until burst is free */
        do
        {
            ret = rte_gpu_comm_get_status(&ring->comm_list[ring->rxi], &s);
            if (ret != 0)
            {
                GpuCommunicationRing::force_quit = true;
                fail("[GPU-RX %d] rte_gpu_comm_get_status error: %s\n", ring->id, rte_strerror(ret));
            }
        } while (s != RTE_GPU_COMM_LIST_FREE);

        /* Capture packets */
        npkts = 0;
        while (ring->force_quit == false && npkts < (ring->burst_size - RTE_RXBURST_ALIGNSIZE))
            npkts += rte_eth_rx_burst(port, ring->id, &(ring->burst[npkts]), (ring->burst_size - npkts));
        if (npkts == 0)
            break;

        /* Get burst timestamp */
        gettimeofday(&tv, NULL);
        ring->headers[ring->rxi * ring->burst_size].ts_sec = tv.tv_sec;
        ring->headers[ring->rxi * ring->burst_size].ts_usec = tv.tv_usec;

        /* Update statistics */
        ring->rxlog.lock();
        ring->stats.packets += npkts;
        for (i = 0; i < npkts; i++)
            ring->stats.total_bytes += ring->burst[i]->data_len;
        ring->rxlog.unlock();

        /* Notify pipeline and pass to next burst */
        ring->rxlist_process(npkts);
        ring->rxi = (ring->rxi + 1) & (ring->ring_size - 1);
    }

    launch_kernel(ring->comm_list + (ring->indices[ring->next] - ring->sbr_size), ring->rxi - (ring->indices[ring->next] - ring->sbr_size), ring->burst_size,
                  ring->stream, ring->ascii_runlen, ring->ascii_percentage, ring->kernel, (ring->headers + ring->indices[ring->current] * ring->burst_size));

    /* Wait for first free burst for notifying */
    do
    {
        ret = rte_gpu_comm_get_status(&ring->comm_list[ring->rxi], &s);
        if (ret != 0)
        {
            GpuCommunicationRing::force_quit = true;
            fail("[GPU-RX %d] rte_gpu_comm_get_status error: %s\n", ring->id, rte_strerror(ret));
        }
    } while (s != RTE_GPU_COMM_LIST_FREE);
    rte_gpu_comm_set_status(&ring->comm_list[ring->rxi], RTE_GPU_COMM_LIST_ERROR);

    return EXIT_SUCCESS;
}

int gpu_dx(void *args)
{
    GpuCommunicationRing *ring = (GpuCommunicationRing *)args;
    enum rte_gpu_comm_list_status s;
    struct rte_mbuf **packets;
    struct pcap_packet_header *headers;
    int i, ret, npkts;

    cudaSetDevice(gpu);
    printf("[GPU-DX %d] Starting...\n", ring->id);

    while (true)
    {
        /* Wait until one queue burst is processed */
        do
        {
            if ((ret = rte_gpu_comm_get_status(&ring->comm_list[ring->dxi], &s)) != 0)
            {
                GpuCommunicationRing::force_quit = true;
                fail("[GPU-RX %d] rte_gpu_comm_get_status error: %s\n", ring->id, rte_strerror(ret));
            }
            if (s == RTE_GPU_COMM_LIST_ERROR)
                return EXIT_SUCCESS;
        } while (s != RTE_GPU_COMM_LIST_DONE);

        /* Obtain burst packets */
        npkts = ring->comm_list[ring->dxi].num_pkts;
        headers = ring->headers + ring->dxi * ring->burst_size;
        packets = ring->comm_list[ring->dxi].mbufs;

        /* Update statistics */
        ring->dxlog.lock();
        for (i = 0; i < npkts; i++)
            ring->stats.stored_bytes += headers[i].caplen;
        ring->dxlog.unlock();

#ifndef SIM_STORAGE
        /* Save burst to disk */
        for (int i = 0; i < npkts; i++)
        {
            fwrite_unlocked(&headers[i], sizeof(pcap_packet_header), 1, ring->pcap_fp);
            fwrite_unlocked((const void *)packets[i]->buf_addr, headers[i].caplen, 1, ring->pcap_fp);
        }
#endif
        /* Return mbufs, notify pipeline and pass to next burst */
        rte_pktmbuf_free_bulk(packets, npkts);
        rte_gpu_comm_cleanup_list(&(ring->comm_list[ring->dxi]));
        ring->dxi = (ring->dxi + 1) & (ring->ring_size - 1);
    }
    return EXIT_SUCCESS;
}
