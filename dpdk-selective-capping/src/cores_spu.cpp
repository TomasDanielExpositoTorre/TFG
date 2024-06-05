#include "headers.h"

int spu_rx(void *args)
{
    SpuCommunicationRing *ring = (SpuCommunicationRing *)args;
    struct timeval tv;
    int ti = 0, i, npkts;

    printf("[SPU-RX %d] Starting...\n", ring->id);

    while (ring->force_quit == false)
    {
        /* Wait until burst is free*/
        while (ring->burst_state[ring->rxi[ti]] != FREE)
            ti = (ti + 1) % ring->nthreads;

        /* Capture packets */
        npkts = 0;
        while (ring->force_quit == false && npkts < (ring->burst_size - RTE_RXBURST_ALIGNSIZE))
            npkts += rte_eth_rx_burst(port, ring->id, &(ring->packet_ring[ring->rxi[ti]][npkts]), (ring->burst_size - npkts));
        if (npkts == 0)
            break;

        /* Get burst timestamp */
        gettimeofday(&tv, NULL);
        ring->headers[ring->rxi[ti] * ring->burst_size].ts_sec = tv.tv_sec;
        ring->headers[ring->rxi[ti] * ring->burst_size].ts_usec = tv.tv_usec;

        /* Update statistics */
        ring->rxlog.lock();
        ring->stats.packets += npkts;

        for (i = 0; i < npkts; i++)
            ring->stats.total_bytes += ring->packet_ring[ring->rxi[ti]][i]->data_len;
        ring->rxlog.unlock();

        /* Notify pipeline and pass to next burst */
        ring->npkts[ring->rxi[ti]] = npkts;
        ring->burst_state[ring->rxi[ti]] = FULL;
        ring->rxi[ti] = ((ring->rxi[ti] + 1) % (ring->subring_size)) + ring->sri[ti];
    }

    /* Wait for first free burst per thread for notifying */
    for (ti = 0; ti < ring->nthreads; ti++)
    {
        while (ring->burst_state[ring->rxi[ti]] != FREE)
            ;
        ring->burst_state[ring->rxi[ti]] = CLOSED;
    }
    return EXIT_SUCCESS;
}

int spu_px(void *args)
{
    SpuCommunicationRing *ring = (SpuCommunicationRing *)args;
    struct rte_mbuf **packets;
    struct pcap_packet_header *headers;
    int npkts, packetlen, runlen, total;
    int id, i, j;
    char *packet;

    id = ring->gettid();

    printf("[SPU-PX %d] Starting...\n", ring->id);

    while (ring->burst_state[ring->pxi[id]] != CLOSED)
    {
        /* Wait until burst is full */
        while (ring->burst_state[ring->pxi[id]] != FULL)
            if (ring->burst_state[ring->pxi[id]] == CLOSED)
                return EXIT_SUCCESS;

        /* Obtain burst packets */
        npkts = ring->npkts[ring->pxi[id]];
        headers = ring->headers + ring->pxi[id] * ring->burst_size;
        packets = ring->packet_ring[ring->pxi[id]];

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
        ring->burst_state[ring->pxi[id]] = PROCESSED;
        ring->pxi[id] = ((ring->pxi[id] + 1) % (ring->subring_size)) + ring->sri[id];
    }
    return EXIT_SUCCESS;
}

int spu_opx(void *args)
{
    SpuCommunicationRing *ring = (SpuCommunicationRing *)args;
    struct rte_mbuf **packets;
    struct pcap_packet_header *headers;
    int npkts, packetlen, seen, total;
    int pxi, sri, i, j, k;
    char *packet;

    pxi = sri = ring->sri[ring->gettid()];

    printf("[SPU-OPX %d] Starting...\n", ring->id);

    while (ring->burst_state[pxi] != CLOSED)
    {
        /* Wait until burst is full */
        while (ring->burst_state[pxi] != FULL)
            if (ring->burst_state[pxi] == CLOSED)
                return EXIT_SUCCESS;

        /* Obtain burst packets */
        npkts = ring->npkts[pxi];
        headers = ring->headers + pxi * ring->burst_size;
        packets = ring->packet_ring[pxi];

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
        ring->burst_state[pxi] = PROCESSED;
        pxi = ((pxi + 1) % (ring->subring_size)) + sri;
    }
    return EXIT_SUCCESS;
}

int spu_dx(void *args)
{
    SpuCommunicationRing *ring = (SpuCommunicationRing *)args;
    struct rte_mbuf **packets;
    struct pcap_packet_header *headers;
    int ti = 0, i, npkts;
    bool finished;

    printf("[SPU-DX %d] Starting...\n", ring->id);
    while (true)
    {
        /* Wait until burst is processed */
        while (ring->burst_state[ring->dxi[ti]] != PROCESSED)
        {
            finished = true;
            for (i = 0; i < ring->nthreads; i++)
                finished &= (ring->burst_state[ring->dxi[i]] == CLOSED);

            if (finished == true)
                return EXIT_SUCCESS;

            ti = (ti + 1) % ring->nthreads;
        }

        /* Obtain burst packets */
        npkts = ring->npkts[ring->dxi[ti]];
        headers = ring->headers + ring->dxi[ti] * ring->burst_size;
        packets = ring->packet_ring[ring->dxi[ti]];

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
        ring->burst_state[ring->dxi[ti]] = FREE;
        ring->dxi[ti] = ((ring->dxi[ti] + 1) % (ring->subring_size)) + ring->sri[ti];
        ti = (ti + 1) % ring->nthreads;
    }
    return EXIT_SUCCESS;
}
