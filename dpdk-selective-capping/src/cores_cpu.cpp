#include "headers.h"

int cpu_rx(void *args)
{
    CpuCommunicationRing *shm = (CpuCommunicationRing *)args;
    struct timeval tv;
    int i, npkts;

    printf("[CPU-RX %d] Starting...\n", shm->id);

    while (shm->force_quit == false)
    {
        while (shm->burst_state[shm->rxi] != BURST_FREE)
            ;

        npkts = 0;

        while (shm->force_quit == false && npkts < (shm->burst_size - RTE_RXBURST_ALIGNSIZE))
            npkts += rte_eth_rx_burst(NIC_PORT, shm->id, &(shm->packet_ring[shm->rxi][npkts]), (shm->burst_size - npkts));

        if (npkts == 0)
            break;

        gettimeofday(&tv, NULL);
        shm->headers[shm->rxi * shm->burst_size].ts_sec = tv.tv_sec;
        shm->headers[shm->rxi * shm->burst_size].ts_usec = tv.tv_usec;

        shm->rxlog.lock();
        shm->stats.packets += npkts;

        for (i = 0; i < npkts; i++)
            shm->stats.total_bytes += shm->packet_ring[shm->rxi][i]->data_len;
        shm->rxlog.unlock();

        shm->npkts[shm->rxi] = npkts;
        shm->burst_state[shm->rxi] = BURST_PROCESSING;
        shm->rxi = (shm->rxi + 1) & (shm->ring_size - 1);
    }

    while (shm->burst_state[shm->rxi] != BURST_FREE)
        ;
    shm->burst_state[shm->rxi] = RX_DONE;

    return EXIT_SUCCESS;
}

int cpu_px(void *args)
{
    CpuCommunicationRing *shm = (CpuCommunicationRing *)args;
    struct rte_mbuf **packets;
    struct pcap_packet_header *headers;
    int npkts, packetlen, runlen, total;
    int i, j;
    char *packet;

    printf("[CPU-PX %d] Starting...\n", shm->id);

    while (shm->burst_state[shm->pxi] != RX_DONE)
    {
        while (shm->burst_state[shm->pxi] != BURST_PROCESSING)
            if (shm->burst_state[shm->pxi] == RX_DONE)
                return EXIT_SUCCESS;

        npkts = shm->npkts[shm->pxi];
        headers = shm->headers + shm->pxi * shm->burst_size;
        packets = shm->packet_ring[shm->pxi];

        for (i = 0; i < npkts; i++)
        {
            packet = (char *)(packets[i]->buf_addr);
            packetlen = packets[i]->data_len;

            headers[i].ts_sec = headers[0].ts_sec;
            headers[i].ts_usec = headers[0].ts_usec;
            headers[i].len = packetlen;

            if (MAX_HLEN >= packetlen)
            {
                headers[i].caplen = packetlen;
                goto next_packet;
            }

            total = 0;
            runlen = 0;

            for (j = MIN_HLEN; j < packetlen; j++)
            {
                if (packet[j] >= MIN_ASCII && packet[j] <= MAX_ASCII)
                {
                    runlen++;
                    total += 100;
                    if (runlen == shm->args.ascii_runlen)
                    {
                        headers[i].caplen = packetlen;
                        goto next_packet;
                    }
                }
                else
                    runlen = 0;
            }

            headers[i].caplen = (total >= (shm->args.ascii_percentage * (packetlen - MIN_HLEN))) ? packetlen : MAX_HLEN;

        next_packet:;
        }

        shm->burst_state[shm->pxi] = BURST_DONE;
        shm->pxi = (shm->pxi + 1) & (shm->ring_size - 1);
    }
    return EXIT_SUCCESS;
}

int cpu_opx(void *args)
{
    CpuCommunicationRing *shm = (CpuCommunicationRing *)args;
    struct rte_mbuf **packets;
    struct pcap_packet_header *headers;
    int npkts, packetlen, seen, total;
    int i, j, k;
    char *packet;

    printf("[CPU-OPX %d] Starting...\n", shm->id);

    while (shm->burst_state[shm->pxi] != RX_DONE)
    {
        while (shm->burst_state[shm->pxi] != BURST_PROCESSING)
            if (shm->burst_state[shm->pxi] == RX_DONE)
                return EXIT_SUCCESS;

        npkts = shm->npkts[shm->pxi];
        headers = shm->headers + shm->pxi * shm->burst_size;
        packets = shm->packet_ring[shm->pxi];

        for (i = 0; i < npkts; i++)
        {
            packet = (char *)(packets[i]->buf_addr);
            packetlen = packets[i]->data_len;

            headers[i].ts_sec = headers[0].ts_sec;
            headers[i].ts_usec = headers[0].ts_usec;
            headers[i].len = packetlen;

            if (MAX_HLEN >= packetlen)
            {
                headers[i].caplen = packetlen;
                goto next_opacket;
            }

            total = 0;
            seen = 0;

            for (j = MIN_HLEN + shm->args.ascii_runlen - 1; j < packetlen; j += shm->args.ascii_runlen)
            {
                seen++;
                if (packet[j] >= MIN_ASCII && packet[j] <= MAX_ASCII)
                {
                    total += 100;
                    for (k = j - 1; k > j - shm->args.ascii_runlen; k--)
                    {
                        seen++;
                        if (packet[k] >= MIN_ASCII && packet[k] <= MAX_ASCII)
                            total += 100;
                        else
                        {
                            j = k;
                            goto end_oloop;
                        }
                    }
                    headers[i].caplen = packetlen;
                    goto next_opacket;
                }
            end_oloop:;
            }

            headers[i].caplen = (total >= (shm->args.ascii_percentage * seen)) ? packetlen : MAX_HLEN;

        next_opacket:;
        }

        shm->burst_state[shm->pxi] = BURST_DONE;
        shm->pxi = (shm->pxi + 1) & (shm->ring_size - 1);
    }
    return EXIT_SUCCESS;
}

int cpu_dx(void *args)
{
    CpuCommunicationRing *shm = (CpuCommunicationRing *)args;
    struct rte_mbuf **packets;
    struct pcap_packet_header *headers;
    int i, npkts;

    printf("[CPU-DX %d] Starting...\n", shm->id);

    while (shm->burst_state[shm->dxi] != RX_DONE)
    {
        while (shm->burst_state[shm->dxi] != BURST_DONE)
            if (shm->burst_state[shm->dxi] == RX_DONE)
                return EXIT_SUCCESS;
        

        npkts = shm->npkts[shm->dxi];
        headers = shm->headers + shm->dxi * shm->burst_size;
        packets = shm->packet_ring[shm->dxi];

        shm->dxlog.lock();
        for (i = 0; i < npkts; i++)
            shm->stats.stored_bytes += headers[i].caplen;
        shm->dxlog.unlock();

        // CommunicationRing::write.lock();
        // for (int i = 0; i < num_pkts; i++)
        // {
        //     fwrite_unlocked(&headers[i], sizeof(pcap_packet_header), 1, shm->pcap_fp);
        //     fwrite_unlocked((const void *)packets[i]->buf_addr, headers[i].caplen, 1, shm->pcap_fp);
        // }
        // CommunicationRing::write.unlock();

        rte_pktmbuf_free_bulk(packets, npkts);
        shm->burst_state[shm->dxi] = BURST_FREE;
        shm->dxi = (shm->dxi + 1) & (shm->ring_size - 1);
    }
    return EXIT_SUCCESS;
}

// int cpu_ndx(void *args)
// {
//     std::vector<CpuCommunicationRing*>& ring = *static_cast<std::vector<CpuCommunicationRing*>*>(args);

//     struct rte_mbuf **packets;
//     struct pcap_packet_header *headers;
//     int dxi = 0, i;
//     int npkts;

//     printf("[CPU-DX] Starting...\n");

//     while (true)
//     {
//         while (shm->burst_state[dxi] != BURST_DONE)
//             if (shm->burst_state[dxi] == RX_DONE)
//                 return EXIT_SUCCESS;
        

//         npkts = shm->npkts[dxi];
//         headers = shm->headers + dxi * shm->burst_size;
//         packets = shm->packet_ring[dxi];

//         shm->dxlog.lock();
//         for (i = 0; i < npkts; i++)
//             shm->stats.stored_bytes += headers[i].caplen;
//         shm->dxlog.unlock();

//         // CommunicationRing::write.lock();
//         // for (int i = 0; i < num_pkts; i++)
//         // {
//         //     fwrite_unlocked(&headers[i], sizeof(pcap_packet_header), 1, shm->pcap_fp);
//         //     fwrite_unlocked((const void *)packets[i]->buf_addr, headers[i].caplen, 1, shm->pcap_fp);
//         // }
//         // CommunicationRing::write.unlock();

//         rte_pktmbuf_free_bulk(packets, npkts);
//         shm->burst_state[dxi] = BURST_FREE;
//         dxi = (dxi + 1) & (shm->ring_size - 1);
//     }
//     return EXIT_SUCCESS;
// }
