#include "headers.h"

int srxcore(void *args)
{
    SpuCommunicationRing *shm = (SpuCommunicationRing *)args;
    int thread = 0, packets;

    printf("[SPU-RX %d] Starting...\n", shm->id);

    while (CommunicationRing::force_quit == false)
    {
        thread = shm->rxlist_choosethread(thread);

        if (thread == -1 || (packets = shm->rxlist_write(thread)) == 0)
            break;

        shm->rxlist_process(thread, packets);
    }
    shm->self_quit = true;
    return EXIT_SUCCESS;
}

int spxcore(void *args)
{
    SpuCommunicationRing *shm = (SpuCommunicationRing *)args;
    struct rte_mbuf **packets;
    struct pcap_packet_header *headers;
    char *packet;
    int num_pkts, psize, runlen, total;
    int id = shm->gettid();

    printf("[SPU-PX %d] Starting normal...\n", shm->id);

    while (shm->self_quit == false || shm->pxlist_isempty(id) == false)
    {
        while (shm->pxlist_isready(id) == false && !(shm->self_quit == true && shm->pxlist_isempty(id)))
            ;

        if (shm->self_quit == true && shm->pxlist_isempty(id))
            return EXIT_SUCCESS;

        packets = shm->pxlist_read(id, &headers, &num_pkts);

        for (int i = 0; i < num_pkts; i++)
        {
            packet = (char *)(packets[i]->buf_addr);
            psize = packets[i]->data_len;

            headers[i].ts_sec = headers[0].ts_sec;
            headers[i].ts_nsec = headers[0].ts_nsec;
            headers[i].len = psize;

            if (MAX_HLEN >= psize)
            {
                headers[i].caplen = psize;
                goto next_packet;
            }

            total = 0;
            runlen = 0;

            for (int j = MIN_HLEN; j < psize; j++)
            {
                if (packet[j] >= MIN_ASCII && packet[j] <= MAX_ASCII)
                {
                    runlen++;
                    total += 100;
                    if (runlen == shm->args.ascii_runlen)
                    {
                        headers[i].caplen = MAX_HLEN;
                        goto next_packet;
                    }
                }
                else
                    runlen = 0;
            }

            headers[i].caplen = (total >= (shm->args.ascii_percentage * (psize - MIN_HLEN))) ? psize : MAX_HLEN;
            
        next_packet:;
        }

        shm->pxlist_done(id);
    }
    return EXIT_SUCCESS;
}

int sopxcore(void *args)
{
    SpuCommunicationRing *shm = (SpuCommunicationRing *)args;
    struct rte_mbuf **packets;
    struct pcap_packet_header *headers;
    char *packet;
    int num_pkts, psize, runlen, total, seen;
    int i,j,k;
    int id = shm->gettid();

    printf("[SPU-OPX %d] Starting optimized...\n", shm->id);

    while (shm->self_quit == false || shm->pxlist_isempty(id) == false)
    {
        while (shm->pxlist_isready(id) == false && !(shm->self_quit == true && shm->pxlist_isempty(id)))
            ;

        if (shm->self_quit == true && shm->pxlist_isempty(id))
            return EXIT_SUCCESS;

        packets = shm->pxlist_read(id, &headers, &num_pkts);

        for (i = 0; i < num_pkts; i++)
        {
            packet = (char *)(packets[i]->buf_addr);
            psize = packets[i]->data_len;

            headers[i].ts_sec = headers[0].ts_sec;
            headers[i].ts_nsec = headers[0].ts_nsec;
            headers[i].len = psize;

            if (MAX_HLEN >= psize)
            {
                headers[i].caplen = psize;
                goto next_opacket;
            }
            
            total = 0;
            seen = 0;

            for (j = MIN_HLEN + shm->args.ascii_runlen - 1; j < psize; j += shm->args.ascii_runlen)
            {
                seen++;
                if (packet[j] >= MIN_ASCII && packet[j] <= MAX_ASCII)
                {
                    runlen = 1;
                    total += 100;
                    for (k = j - 1; k > j - shm->args.ascii_runlen; k--)
                    {
                        seen++;
                        if (packet[k] >= MIN_ASCII && packet[k] <= MAX_ASCII)
                        {
                            runlen++;
                            total += 100;
                        }
                        else
                        {
                            j = k;
                            goto end_oloop;
                        }
                    }
                end_oloop:
                    if (runlen == shm->args.ascii_runlen)
                    {
                        headers[i].caplen = MAX_HLEN;
                        goto next_opacket;
                    }
                }
            }

            headers[i].caplen = (total >= (shm->args.ascii_percentage * seen)) ? psize : MAX_HLEN;

        next_opacket:;
        }
        shm->pxlist_done(id);
    }
    return EXIT_SUCCESS;
}

int sdxcore(void *args)
{
    SpuCommunicationRing *shm = (SpuCommunicationRing *)args;
    struct rte_mbuf **packets;
    struct pcap_packet_header *headers;
    int num_pkts, thread = 0;

    printf("[SPU-DX %d] Starting...\n", shm->id);

    while (shm->self_quit == false || shm->dxlist_isempty() == false)
    {
        thread = shm->dxlist_choosethread(thread);

        if (thread == -1)
            return EXIT_SUCCESS;

        packets = shm->dxlist_read(thread, &headers, &num_pkts);

        shm->dxlog.lock();
        for (int i = 0; i < num_pkts; i++)
            shm->stats.stored_bytes += headers[i].caplen;
        shm->dxlog.unlock();

        // CommunicationRing::write.lock();
        // for (int i = 0; i < num_pkts; i++)
        // {
        //     fwrite_unlocked(&headers[i], sizeof(pcap_packet_header), 1, shm->pcap_fp);
        //     fwrite_unlocked((const void *)packets[i]->buf_addr, headers[i].caplen, 1, shm->pcap_fp);
        // }
        // CommunicationRing::write.unlock();
        shm->dxlist_clean(thread);
    }
    return EXIT_SUCCESS;
}
