#include "headers.h"

int spu_rx(void *args)
{
    SpuCommunicationRing *shm = (SpuCommunicationRing *)args;
    struct timeval tv;
    int ti = 0, i, npkts;

    printf("[SPU-RX %d] Starting...\n", shm->id);

    while (shm->force_quit == false)
    {
        while (shm->burst_state[shm->rxi[ti]] != BURST_FREE)
            ti = (ti + 1) % shm->nthreads;

        npkts = 0;

        while (shm->force_quit == false && npkts < (shm->burst_size - RTE_RXBURST_ALIGNSIZE))
            npkts += rte_eth_rx_burst(NIC_PORT, shm->id, &(shm->packet_ring[shm->rxi[ti]][npkts]), (shm->burst_size - npkts));

        if (npkts == 0)
            break;

        gettimeofday(&tv, NULL);
        shm->headers[shm->rxi[ti] * shm->burst_size].ts_sec = tv.tv_sec;
        shm->headers[shm->rxi[ti] * shm->burst_size].ts_usec = tv.tv_usec;

        shm->rxlog.lock();
        shm->stats.packets += npkts;

        for (i = 0; i < npkts; i++)
            shm->stats.total_bytes += shm->packet_ring[shm->rxi[ti]][i]->data_len;
        shm->rxlog.unlock();

        shm->npkts[shm->rxi[ti]] = npkts;
        shm->burst_state[shm->rxi[ti]] = BURST_PROCESSING;
        shm->rxi[ti] = ((shm->rxi[ti] + 1) % (shm->subring_size)) + shm->sri[ti];
    }

    for (ti = 0; ti < shm->nthreads; ti++)
    {
        while (shm->burst_state[shm->rxi[ti]] != BURST_FREE)
            ;
        shm->burst_state[shm->rxi[ti]] = RX_DONE;
    }
    return EXIT_SUCCESS;
}

int spu_px(void *args)
{
    SpuCommunicationRing *shm = (SpuCommunicationRing *)args;
    struct rte_mbuf **packets;
    struct pcap_packet_header *headers;
    int npkts, packetlen, runlen, total;
    int id, i, j;
    char *packet;

    id = shm->gettid();

    printf("[SPU-PX %d] Starting...\n", shm->id);

    while (shm->burst_state[shm->pxi[id]] != RX_DONE)
    {
        while (shm->burst_state[shm->pxi[id]] != BURST_PROCESSING)
            if (shm->burst_state[shm->pxi[id]] == RX_DONE)
                return EXIT_SUCCESS;

        npkts = shm->npkts[shm->pxi[id]];
        headers = shm->headers + shm->pxi[id] * shm->burst_size;
        packets = shm->packet_ring[shm->pxi[id]];

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

        shm->burst_state[shm->pxi[id]] = BURST_DONE;
        shm->pxi[id] = ((shm->pxi[id] + 1) % (shm->subring_size)) + shm->sri[id];
    }
    return EXIT_SUCCESS;
}

int spu_opx(void *args)
{
    SpuCommunicationRing *shm = (SpuCommunicationRing *)args;
    struct rte_mbuf **packets;
    struct pcap_packet_header *headers;
    int npkts, packetlen, seen, total;
    int pxi, sri, i, j, k;
    char *packet;

    pxi = sri = shm->sri[shm->gettid()];

    printf("[SPU-OPX %d] Starting...\n", shm->id);

    while (shm->burst_state[pxi] != RX_DONE)
    {
        while (shm->burst_state[pxi] != BURST_PROCESSING)
            if (shm->burst_state[pxi] == RX_DONE)
                return EXIT_SUCCESS;

        npkts = shm->npkts[pxi];
        headers = shm->headers + pxi * shm->burst_size;
        packets = shm->packet_ring[pxi];

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

        shm->burst_state[pxi] = BURST_DONE;
        pxi = ((pxi + 1) % (shm->subring_size)) + sri;
    }
    return EXIT_SUCCESS;
}

int spu_dx(void *args)
{
    SpuCommunicationRing *shm = (SpuCommunicationRing *)args;
    struct rte_mbuf **packets;
    struct pcap_packet_header *headers;
    int ti = 0, i, npkts;
    bool finished;

    printf("[SPU-DX %d] Starting...\n", shm->id);
    while (true)
    {
        while (shm->burst_state[shm->dxi[ti]] != BURST_DONE)
        {
            finished = true;
            for (i = 0; i < shm->nthreads; i++)
                finished &= (shm->burst_state[shm->dxi[i]] == RX_DONE);

            if (finished == true)
                return EXIT_SUCCESS;

            ti = (ti + 1) % shm->nthreads;
        }

        npkts = shm->npkts[shm->dxi[ti]];
        headers = shm->headers + shm->dxi[ti] * shm->burst_size;
        packets = shm->packet_ring[shm->dxi[ti]];

        shm->dxlog.lock();
        for (i = 0; i < npkts; i++)
            shm->stats.stored_bytes += headers[i].caplen;
        shm->dxlog.unlock();

#ifndef SIM_STORAGE
        for (int i = 0; i < npkts; i++)
        {
            fwrite_unlocked(&headers[i], sizeof(pcap_packet_header), 1, shm->pcap_fp);
            fwrite_unlocked((const void *)packets[i]->buf_addr, headers[i].caplen, 1, shm->pcap_fp);
        }
#endif

        rte_pktmbuf_free_bulk(packets, npkts);
        shm->burst_state[shm->dxi[ti]] = BURST_FREE;
        shm->dxi[ti] = ((shm->dxi[ti] + 1) % (shm->subring_size)) + shm->sri[ti];
        ti = (ti + 1) % shm->nthreads;
    }
    return EXIT_SUCCESS;
}