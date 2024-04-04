#include "headers.h"
#include <mutex>

error_t parse_opt(int key, char *arg, struct argp_state *state)
{
    struct arguments *args = (struct arguments *)state->input;
    int min_cores;

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
        if (args->ascii_runlen <= 0 || args->ascii_runlen > RTE_ETHER_MAX_LEN)
        {
            fprintf(stderr, "[Error] Incorrect ASCII runlen. Value must be a postive number.\n");
            exit(EXIT_FAILURE);
        }
        break;
    case 'k':
        args->kernel = atoi(arg);
        if (args->kernel < VANILLA_CAPPING_THREAD || args->kernel > COERCIVE_CAPPING_WARP)
        {
            fprintf(stderr, "[Error] Incorrect kernel type. Value must be from %d to %d.\n",
                    VANILLA_CAPPING_THREAD, COERCIVE_CAPPING_WARP);
            exit(EXIT_FAILURE);
        }
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

/* ========================================================================= */
/* ===========================   GPU  WORKLOAD   =========================== */
/* ========================================================================= */

int gpu_rxcore(void *args)
{
    GpuCommunicationRing *shm = (GpuCommunicationRing *)args;
    struct rte_mbuf *packets[MAX_BURSTSIZE];
    int i, ret;

    printf("[R-Core %d] Starting...\n", shm->id);
    cudaSetDevice(GPU_ID);

    while (CommunicationRing::force_quit == false)
    {
        i = 0;

        while (shm->rxlist_iswritable(&ret) == false)
            if (ret != 0)
            {
                fprintf(stderr, "[R-Core %d] rte_gpu_comm_get_status error: %s\n", shm->id, rte_strerror(ret));
                GpuCommunicationRing::force_quit = true;
                return EXIT_FAILURE;
            }

        /* Populate burst */
        while (keep_alive(shm) && i < (shm->burst_size - RTE_RXBURST_ALIGNSIZE))
            i += rte_eth_rx_burst(NIC_PORT, shm->id, &(packets[i]), (shm->burst_size - i));

        if (i == 0)
            break;

        shm->npackets.lock();
        shm->stats.packets += i;
        shm->npackets.unlock();

        if (shm->rxlist_write(packets, i) != 0)
        {
            fprintf(stderr, "[R-Core %d] rte_gpu_comm_populate_list_pkts error: %s\n", shm->id, rte_strerror(ret));
            GpuCommunicationRing::force_quit = true;
            return EXIT_FAILURE;
        }
        shm->rxlist_process(ceil(i, 32), 32);
    }
    shm->self_quit = true;
    return EXIT_SUCCESS;
}

int gpu_dxcore(void *args)
{
    GpuCommunicationRing *shm = (GpuCommunicationRing *)args;
    struct rte_gpu_comm_list *comm_list;
    struct pcap_packet_header burst_header;
    bool cap_packet;
    int ret = 0;

    printf("[D-Core %d] Starting...\n", shm->id);
    cudaSetDevice(GPU_ID);

    while (shm->self_quit == false || shm->dxlist_isempty() == false)
    {
        while (shm->dxlist_isreadable(&ret) == false && !(shm->self_quit == true && shm->dxlist_isempty()))
            if (ret != 0)
            {
                fprintf(stderr, "[D-Core %d] rte_gpu_comm_get_status error: %s\n", shm->id, rte_strerror(ret));
                GpuCommunicationRing::force_quit = true;
                return EXIT_FAILURE;
            }

        if (shm->self_quit == true && shm->dxlist_isempty())
            break;

        comm_list = shm->dxlist_read(&burst_header);

        for (uint32_t i = 0; i < comm_list->num_pkts; i++)
        {
            cap_packet = comm_list->pkt_list[i].size & 1;
            comm_list->pkt_list[i].size >>= 1;
            burst_header.caplen = (cap_packet && MAX_HLEN < comm_list->pkt_list[i].size) ? MAX_HLEN : comm_list->pkt_list[i].size;
            burst_header.len = comm_list->pkt_list[i].size;

            shm->nbytes.lock();
            shm->stats.total_bytes += burst_header.len;
            shm->stats.stored_bytes += burst_header.caplen;
            shm->nbytes.unlock();

            // GpuCommunicationRing::write.lock();
            // fwrite_unlocked(&(burst_header), sizeof(pcap_packet_header), 1, shm->pcap_fp);
            // fwrite_unlocked((const void *)comm_list->pkt_list[i].addr, burst_header.caplen, 1, shm->pcap_fp);
            // GpuCommunicationRing::write.unlock();
        }
        rte_pktmbuf_free_bulk(comm_list->mbufs, comm_list->num_pkts);
        shm->dxlist_clean();
    }
    return EXIT_SUCCESS;
}
/* ========================================================================= */
/* ===========================   CPU  WORKLOAD   =========================== */
/* ========================================================================= */

int cpu_rxcore(void *args)
{
    CpuCommunicationRing *shm = (CpuCommunicationRing *)args;
    int i;

    printf("[R-Core %d] Starting...\n", shm->id);

    while (CpuCommunicationRing::force_quit == false)
    {
        while (shm->rxlist_iswritable() == false)
            ;

        if ((i = shm->rxlist_write()) == 0)
            break;

        shm->npackets.lock();
        shm->stats.packets += i;
        shm->npackets.unlock();

        shm->rxlist_process();
    }
    shm->self_quit = true;
    return EXIT_SUCCESS;
}

int cpu_pxcore(void *args)
{
    CpuCommunicationRing *shm = (CpuCommunicationRing *)args;
    struct rte_mbuf **packets;
    char *packet;
    int num_pkts, packetlen, runlen, total;

    printf("[P-Core %d] Starting...\n", shm->id);

    while (shm->self_quit == false || shm->pxlist_isempty() == false)
    {
        while (shm->pxlist_isready() == false && !(shm->self_quit == true && shm->pxlist_isempty()))
            ;

        if (shm->self_quit == true && shm->pxlist_isempty())
            break;

        packets = shm->pxlist_read(&num_pkts);

        for (int i = 0; i < num_pkts; i++)
        {
            packet = (char *)(packets[i]->buf_addr);
            packetlen = packets[i]->data_len;
            packets[i]->data_len <<= 1;

            for (int j = MIN_HLEN; j < packetlen; j++)
            {
                if (packet[j] >= MIN_ASCII && packet[j] <= MAX_ASCII)
                {
                    runlen++;
                    total += 100;
                    if (runlen == shm->cargs.ascii_runlen)
                        j = packetlen;
                }
                else
                    runlen = 0;
            }

            packets[i]->data_len |= (runlen < shm->cargs.ascii_runlen || total < (shm->cargs.ascii_percentage * (packetlen - MIN_HLEN)));
        }

        shm->pxlist_done();
    }
    return EXIT_SUCCESS;
}

int cpu_dxcore(void *args)
{
    CpuCommunicationRing *shm = (CpuCommunicationRing *)args;
    struct rte_mbuf **packets;
    struct pcap_packet_header burst_header;
    bool cap_packet;
    int num_pkts;

    printf("[D-Core %d] Starting...\n", shm->id);

    while (shm->self_quit == false || shm->dxlist_isempty() == false)
    {
        while (shm->dxlist_isreadable() == false && !(shm->self_quit == true && shm->dxlist_isempty()))
            ;

        if (shm->self_quit == true && shm->dxlist_isempty())
            break;

        packets = shm->dxlist_read(&burst_header, &num_pkts);

        for (int i = 0; i < num_pkts; i++)
        {
            cap_packet = packets[i]->data_len & 1;
            packets[i]->data_len >>= 1;
            burst_header.caplen = (cap_packet && MAX_HLEN < packets[i]->data_len) ? MAX_HLEN : packets[i]->data_len;
            burst_header.len = packets[i]->data_len;

            shm->nbytes.lock();
            shm->stats.total_bytes += burst_header.len;
            shm->stats.stored_bytes += burst_header.caplen;
            shm->nbytes.unlock();

            // CommunicationRing::write.lock();
            // fwrite_unlocked(&(burst_header), sizeof(pcap_packet_header), 1, shm->pcap_fp);
            // fwrite_unlocked((const void *)packets[i]->buf_addr, burst_header.caplen, 1, shm->pcap_fp);
            // CommunicationRing::write.unlock();
        }
        shm->dxlist_clean();
    }
    return EXIT_SUCCESS;
}
