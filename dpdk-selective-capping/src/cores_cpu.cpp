#include "headers.h"

int cpu_rx(void *args)
{
    CpuCommunicationRing *ring = (CpuCommunicationRing *)args;
    struct timeval tv;
    int i, npkts;
    unsigned long long j=0;
    printf("[CPU-RX %d] Starting...\n", ring->id);

    while (ring->force_quit == false)
    {
        j++;
        /* Wait until burst is free*/
        while (ring->burst_state[ring->rxi] != FREE)
            ;

        /* Capture packets */
        npkts = 0;
        while (ring->force_quit == false && npkts < (ring->burst_size - RTE_RXBURST_ALIGNSIZE))
            npkts += rte_eth_rx_burst(port, ring->id, &(ring->packet_ring[ring->rxi][npkts]), (ring->burst_size - npkts));
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
            ring->stats.total_bytes += ring->packet_ring[ring->rxi][i]->data_len;
        ring->rxlog.unlock();

        /* Notify pipeline and pass to next burst */
        ring->npkts[ring->rxi] = npkts;
        ring->burst_state[ring->rxi] = FULL;
        ring->rxi = (ring->rxi + 1) & (ring->ring_size - 1);
    }

    /* Wait for first free burst for notifying */
    while (ring->burst_state[ring->rxi] != FREE)
        ;
    ring->burst_state[ring->rxi] = CLOSED;

    printf("rx %lld\n", j);

    return EXIT_SUCCESS;
}

int cpu_px(void *args)
{
    CpuCommunicationRing *ring = (CpuCommunicationRing *)args;
    struct rte_mbuf **packets;
    struct pcap_packet_header *headers;
    int npkts, packetlen, runlen, total;
    int i, j;
    char *packet;
    unsigned long long ll=0;

    printf("[CPU-PX %d] Starting...\n", ring->id);

    while (ring->burst_state[ring->pxi] != CLOSED)
    {
        ll++;
        /* Wait until burst is full */
        while (ring->burst_state[ring->pxi] != FULL)
            if (ring->burst_state[ring->pxi] == CLOSED)
                return EXIT_SUCCESS;

        /* Obtain burst packets */
        npkts = ring->npkts[ring->pxi];
        headers = ring->headers + ring->pxi * ring->burst_size;
        packets = ring->packet_ring[ring->pxi];

        /* Vanilla Capping */
        for (i = 0; i < npkts; i++)
        {
            packet = (char *)(packets[i]->buf_addr);
            packetlen = packets[i]->data_len;

            /* Broadcast timestamp and fill header */
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
                    if (runlen == ring->ascii_runlen)
                    {
                        headers[i].caplen = packetlen;
                        goto next_packet;
                    }
                }
                else
                    runlen = 0;
            }

            headers[i].caplen = (total >= (ring->ascii_percentage * (packetlen - MIN_HLEN))) ? packetlen : MAX_HLEN;

        next_packet:;
        }

        /* Notify pipeline and pass to next burst */
        ring->burst_state[ring->pxi] = PROCESSED;
        ring->pxi = (ring->pxi + 1) & (ring->ring_size - 1);
    }
    printf("px %lld\n", ll);

    return EXIT_SUCCESS;
}

int cpu_opx(void *args)
{
    CpuCommunicationRing *ring = (CpuCommunicationRing *)args;
    struct rte_mbuf **packets;
    struct pcap_packet_header *headers;
    int npkts, packetlen, seen, total;
    int i, j, k;
    char *packet;

    printf("[CPU-OPX %d] Starting...\n", ring->id);

    while (ring->burst_state[ring->pxi] != CLOSED)
    {
        /* Wait until burst is full */
        while (ring->burst_state[ring->pxi] != FULL)
            if (ring->burst_state[ring->pxi] == CLOSED)
                return EXIT_SUCCESS;

        /* Obtain burst packets */
        npkts = ring->npkts[ring->pxi];
        headers = ring->headers + ring->pxi * ring->burst_size;
        packets = ring->packet_ring[ring->pxi];

        /* Optimized Capping */
        for (i = 0; i < npkts; i++)
        {
            packet = (char *)(packets[i]->buf_addr);
            packetlen = packets[i]->data_len;

            /* Broadcast timestamp and fill header */
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

            for (j = MIN_HLEN + ring->ascii_runlen - 1; j < packetlen; j += ring->ascii_runlen)
            {
                seen++;
                if (packet[j] >= MIN_ASCII && packet[j] <= MAX_ASCII) /* Start of run found, iterate backwards*/
                {
                    total += 100;
                    for (k = j - 1; k > j - ring->ascii_runlen; k--)
                    {
                        seen++;
                        if (packet[k] >= MIN_ASCII && packet[k] <= MAX_ASCII)
                            total += 100;
                        else
                        {
                            j = k;
                            goto end_oloop; /* Run finished early, skip L bytes*/
                        }
                    }
                    headers[i].caplen = packetlen; /* Run finished, do not cap */
                    goto next_opacket; 
                }
            end_oloop:;
            }

            headers[i].caplen = (total >= (ring->ascii_percentage * seen)) ? packetlen : MAX_HLEN;

        next_opacket:;
        }

        /* Notify pipeline and pass to next burst */
        ring->burst_state[ring->pxi] = PROCESSED;
        ring->pxi = (ring->pxi + 1) & (ring->ring_size - 1);
    }
    return EXIT_SUCCESS;
}

int cpu_dx(void *args)
{
    CpuCommunicationRing *ring = (CpuCommunicationRing *)args;
    struct rte_mbuf **packets;
    struct pcap_packet_header *headers;
    int i, npkts;

    printf("[CPU-DX %d] Starting...\n", ring->id);

    while (ring->burst_state[ring->dxi] != CLOSED)
    {
        /* Wait until burst is processed */
        while (ring->burst_state[ring->dxi] != PROCESSED)
            if (ring->burst_state[ring->dxi] == CLOSED)
                return EXIT_SUCCESS;

        /* Obtain burst packets */
        npkts = ring->npkts[ring->dxi];
        headers = ring->headers + ring->dxi * ring->burst_size;
        packets = ring->packet_ring[ring->dxi];

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
        ring->burst_state[ring->dxi] = FREE;
        ring->dxi = (ring->dxi + 1) & (ring->ring_size - 1);
    }
    return EXIT_SUCCESS;
}

int cpu_ndx(void *args)
{
    std::vector<CpuCommunicationRing *> &ring = *static_cast<std::vector<CpuCommunicationRing *> *>(args);

    struct rte_mbuf **packets;
    struct pcap_packet_header *headers;
    int npkts, nrings = ring.size();
    int i, ti = 0;
    bool finished;

    printf("[CPU-DX] Starting...\n");

    while (true)
    {
        /* Wait until one queue burst is processed */
        while (ring[ti]->burst_state[ring[ti]->dxi] != PROCESSED)
        {
            finished = true;
            for (i = 0; i < nrings; i++)
                finished &= (ring[ti]->burst_state[ring[ti]->dxi] == CLOSED);

            /* Exit if all queues are closed */
            if (finished == true) 
                return EXIT_SUCCESS;

            ti = (ti + 1) % nrings;
        }

        /* Obtain burst packets */
        npkts = ring[ti]->npkts[ring[ti]->dxi];
        headers = ring[ti]->headers + ring[ti]->dxi * ring[ti]->burst_size;
        packets = ring[ti]->packet_ring[ring[ti]->dxi];

        /* Update statistics */
        ring[ti]->dxlog.lock();
        for (i = 0; i < npkts; i++)
            ring[ti]->stats.stored_bytes += headers[i].caplen;
        ring[ti]->dxlog.unlock();

#ifndef SIM_STORAGE
        /* Save burst to disk */
        for (int i = 0; i < npkts; i++)
        {
            fwrite_unlocked(&headers[i], sizeof(pcap_packet_header), 1, ring[ti]->pcap_fp);
            fwrite_unlocked((const void *)packets[i]->buf_addr, headers[i].caplen, 1, ring[ti]->pcap_fp);
        }
#endif
        /* Return mbufs, notify pipeline and pass to next burst */
        rte_pktmbuf_free_bulk(packets, npkts);
        ring[ti]->burst_state[ring[ti]->dxi] = FREE;
        ring[ti]->dxi = (ring[ti]->dxi + 1) & (ring[ti]->ring_size - 1);
    }
    return EXIT_SUCCESS;
}
