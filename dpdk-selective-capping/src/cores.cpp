#include "headers.h"
#include <mutex>

error_t parse_opt(int key, char *arg, struct argp_state *state)
{
    struct arguments *args = (struct arguments *)state->input;
    switch (key)
    {
    case 'p':
        args->ascii_percentage = atoi(arg);
        if (args->ascii_percentage <= 0 || args->ascii_percentage > 100)
        {
            fprintf(stderr, "[Error] Incorrect ASCII percentage. Value must be from 1 to 100.\n");
            exit(EXIT_FAILURE);
        }
        break;
    case 'r':
        args->ascii_runlen = atoi(arg);
        if (args->ascii_runlen <= 0 || args->ascii_runlen > (RTE_ETHER_MAX_LEN - MIN_HLEN))
        {
            fprintf(stderr, "[Error] Incorrect ASCII runlen. Value must be a valid number for ethernet packets.\n");
            exit(EXIT_FAILURE);
        }
        break;
    case 'k':
        args->kernel = atoi(arg) % 2;
        break;
    case 'o':
        if ((args->output = fopen(arg, "wb")) == NULL)
        {
            perror("fopen");
            exit(EXIT_FAILURE);
        }
        break;
    case 'q':
        args->queues = atoi(arg);
        if (args->queues <= 0)
        {
            fprintf(stderr, "[Error] Number of queues cannot be 0.\n");
            exit(EXIT_FAILURE);
        }
        break;
    case 'c':
        args->ring_size = atoi(arg);
        if (args->ring_size <= 0)
        {
            fprintf(stderr, "[Error] Number of bursts for communication list must be greater than 0.\n");
            exit(EXIT_FAILURE);
        }
    case 'b':
        args->burst_size = atoi(arg);
        if (args->burst_size <= 0)
        {
            fprintf(stderr, "[Error] Burst size must be greater than 0.\n");
            exit(EXIT_FAILURE);
        }
        break;
    case 'w':
        args->gpu_workload = atoi(arg) % 2;
        break;
    default:
        return ARGP_ERR_UNKNOWN;
    }
    return 0;
}

void mastercore(std::vector<CommunicationRing *> &shmem, struct arguments args)
{
    struct rte_eth_stats stats;
    int id, ret, time_elapsed = 0;
    float pps, sbps, tbps;
    char su, tu;

    sleep(5);
    while (CommunicationRing::force_quit == false)
    {
        rte_eth_stats_get(NIC_PORT, &stats);
        time_elapsed += 5;

        puts("\n---------------------------------------------------------------------");
        printf("\nTime elapsed: %02d:%02d:%02d\n",
               time_elapsed / 3600,
               time_elapsed / 60 % 60,
               time_elapsed % 60);
        puts("Capture ring information");
        for (id = 0; id < args.queues; id++)
            printf("Queue %d: %lu bytes, %lu packets received, %lu packets dropped\n",
                   id,
                   stats.q_ibytes[id],
                   stats.q_ipackets[id],
                   stats.q_errors[id]);

        puts("\nProcessing ring information");
        for (auto &it : shmem)
        {
            it->rxlog.lock();
            it->dxlog.lock();
            pps = it->stats.packets;
            tbps = it->stats.total_bytes;
            sbps = it->stats.stored_bytes;
            it->dxlog.unlock();
            it->rxlog.unlock();

            pps /= time_elapsed;
            tbps = (tbps * 8) / time_elapsed;
            sbps = (sbps * 8) / time_elapsed;

            speed_format(tbps, tu);
            speed_format(sbps, su);

            printf("Queue %d: %.2f pps, %.2f %cbps (total), %.2f %cbps (stored)\n",
                   it->id, pps, tbps, tu, sbps, su);
        }
        sleep(5);
    }

    RTE_WAIT_WORKERS(id, ret);
    rte_eth_stats_get(NIC_PORT, &stats);

    puts("\n---------------------------------------------------------------------");
    puts("Exiting program...");
    puts("Capture ring information");
    for (id = 0; id < args.queues; id++)
        printf("Queue %d: %lu bytes, %lu packets received, %lu packets dropped\n",
               id,
               stats.q_ibytes[id],
               stats.q_ipackets[id],
               stats.q_errors[id]);
    puts("\nProcessing ring information");
    for (auto &it : shmem)
    {
        tbps = it->stats.total_bytes * 8;
        sbps = it->stats.stored_bytes * 8;
        speed_format(tbps, tu);
        speed_format(sbps, su);

        printf("Queue %d: %lu packets, %.2f %cb (total), %.2f %cb (stored)\n",
               it->id, it->stats.packets, tbps, tu, sbps, su);
    }
}

/* ========================================================================= */
/* ===========================   GPU  WORKLOAD   =========================== */
/* ========================================================================= */

int rxcore(void *args)
{
    CommunicationRing *shm = (CommunicationRing *)args;
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

int dxcore(void *args)
{
    GpuCommunicationRing *shm = (GpuCommunicationRing *)args;
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
/* ========================================================================= */
/* ===========================   CPU  WORKLOAD   =========================== */
/* ========================================================================= */

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
            break;

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
int pxcore_optimized(void *args)
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
            break;

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