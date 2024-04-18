#include "headers.h"

int rxcore(void *args)
{
    LinearCommunicationRing *shm = (LinearCommunicationRing *)args;
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

int pxcore(void *args)
{
    CpuCommunicationRing *shm = (CpuCommunicationRing *)args;
    struct rte_mbuf **packets;
    struct pcap_packet_header *headers;
    char *packet;
    int num_pkts, psize, runlen, total;

    printf("[CPU-PX %d] Starting...\n", shm->id);

    while (shm->self_quit == false || shm->pxlist_isempty() == false)
    {
        while (shm->pxlist_isready() == false && !(shm->self_quit == true && shm->pxlist_isempty()))
            ;

        if (shm->self_quit == true && shm->pxlist_isempty())
            return EXIT_SUCCESS;

        packets = shm->pxlist_read(&num_pkts, &headers);

        for (int i = 0; i < num_pkts; i++)
        {
            packet = (char *)(packets[i]->buf_addr);
            psize = packets[i]->data_len;

            headers[i].ts_sec = headers[0].ts_sec;
            headers[i].ts_nsec = headers[0].ts_nsec;
            headers[i].len = psize;

            total = 0;
            runlen = 0;

            for (int j = MIN_HLEN; j < psize; j++)
            {
                if (packet[j] >= MIN_ASCII && packet[j] <= MAX_ASCII)
                {
                    runlen++;
                    total += 100;
                    if (runlen == shm->args.ascii_runlen)
                        j = psize;
                }
                else
                    runlen = 0;
            }

            if (MAX_HLEN > psize || runlen == shm->args.ascii_runlen || total >= (shm->args.ascii_percentage * (psize - MIN_HLEN)))
                headers[i].caplen = psize;
            else
                headers[i].caplen = MAX_HLEN;
        }

        shm->pxlist_done();
    }
    return EXIT_SUCCESS;
}

int opxcore(void *args)
{
    CpuCommunicationRing *shm = (CpuCommunicationRing *)args;
    struct rte_mbuf **packets;
    struct pcap_packet_header *headers;
    char *packet;
    int num_pkts, psize, runlen, total, seen;

    printf("[CPU-PX %d] Starting...\n", shm->id);

    while (shm->self_quit == false || shm->pxlist_isempty() == false)
    {
        while (shm->pxlist_isready() == false && !(shm->self_quit == true && shm->pxlist_isempty()))
            ;

        if (shm->self_quit == true && shm->pxlist_isempty())
            return EXIT_SUCCESS;

        packets = shm->pxlist_read(&num_pkts, &headers);

        for (int i = 0; i < num_pkts; i++)
        {
            packet = (char *)(packets[i]->buf_addr);
            psize = packets[i]->data_len;

            headers[i].ts_sec = headers[0].ts_sec;
            headers[i].ts_nsec = headers[0].ts_nsec;
            headers[i].len = psize;

            total = 0;
            runlen = 0;
            seen = 0;
            for (int j = MIN_HLEN + shm->args.ascii_runlen - 1; j >= MIN_HLEN && j < psize; j--, seen++)
            {
                if (packet[j] >= MIN_ASCII && packet[j] <= MAX_ASCII)
                {
                    runlen++;
                    total += 100;
                    if (runlen == shm->args.ascii_runlen)
                        j = psize;
                }
                else
                {
                    runlen = 0;
                    j += shm->args.ascii_runlen + 1;
                }
            }

            if (MAX_HLEN > psize || runlen == shm->args.ascii_runlen || total >= (shm->args.ascii_percentage * seen))
                headers[i].caplen = psize;
            else
                headers[i].caplen = MAX_HLEN;
        }
        shm->pxlist_done();
    }
    return EXIT_SUCCESS;
}

int dxcore(void *args)
{
    LinearCommunicationRing *shm = (LinearCommunicationRing *)args;
    struct rte_mbuf **packets;
    struct pcap_packet_header *headers;
    int num_pkts;

    if (shm->args.gpu_workload == true)
        cudaSetDevice(GPU_ID);
    printf("[%cPU-DX %d] Starting...\n", shm->args.gpu_workload ? 'G' : 'C', shm->id);

    while (shm->self_quit == false || shm->dxlist_isempty() == false)
    {
        while (shm->dxlist_isreadable() == false && !(shm->self_quit == true && shm->dxlist_isempty()))
            ;

        if (shm->self_quit == true && shm->dxlist_isempty())
            break;

        packets = shm->dxlist_read(&headers, &num_pkts);

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
        shm->dxlist_clean();
    }
    return EXIT_SUCCESS;
}
