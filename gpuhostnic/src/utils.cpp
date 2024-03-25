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
            fprintf(stderr, "Incorrect ASCII percentage. Value must be from 1 to 100\n");
            exit(EXIT_FAILURE);
        }
        break;
    case 'r':
        args->ascii_runlen = atoi(arg);
        if (args->ascii_runlen <= 0 || args->ascii_runlen > RTE_ETHER_MAX_LEN)
        {
            fprintf(stderr, "Incorrect ASCII runlen. Value must be a postive number\n");
            exit(EXIT_FAILURE);
        }
        break;
    case 'k':
        args->kernel = atoi(arg);
        if (args->kernel < VANILLA_CAPPING_THREAD || args->kernel > COERCIVE_CAPPING_WARP)
        {
            fprintf(stderr, "Incorrect kernel type. Value must be from %d to %d\n",
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
        min_cores = 2 * args->queues + 2;
        if (args->queues <= 0)
        {
            fprintf(stderr, "Number of queues cannot be 0.\n");
            exit(EXIT_FAILURE);
        }
        if (min_cores > (int)rte_lcore_count())
        {
            fprintf(stderr, "[Error] Number of cores should be at least %d to suppport %d queues.\n", min_cores, args->queues);
            exit(EXIT_FAILURE);
        }
        break;
    default:
        return ARGP_ERR_UNKNOWN;
    }
    return 0;
}

int print_stats(void *args)
{
    struct rte_eth_stats stats;
    std::vector<GpuHostNicShmem *> &shm = *reinterpret_cast<std::vector<GpuHostNicShmem *> *>(args);
    int id, queues = shm.size();
    int time_elapsed = 0;

    sleep(5);
    while (GpuHostNicShmem::force_quit == false)
    {
        rte_eth_stats_get(NIC_PORT, &stats);
        time_elapsed += 5;

        puts("\n---------------------------------------------------------------------");
        printf("\nTime elapsed: %dh,%dm,%ds\n",
               time_elapsed / 3600,
               time_elapsed / 60 % 60,
               time_elapsed % 60);
        puts("DPDK queue information");
        for (id = 0; id < queues; id++)
            printf("Queue %d: %lu bytes, %lu packets received, %lu packets dropped\n",
                   id,
                   stats.q_ibytes[id],
                   stats.q_ipackets[id],
                   stats.q_errors[id]);
        puts("\nGpuHostNic queue information");
        for (auto &it : shm)
            printf("Queue %d: %.2f pps, %.2f bps (total), %.2f bps (stored)\n",
                   it->id,
                   (float)(it->stats.packets / time_elapsed),
                   (float)(it->stats.total_bytes * 8 / time_elapsed),
                   (float)(it->stats.stored_bytes * 8 / time_elapsed));
        sleep(5);
    }

    return EXIT_SUCCESS;
}

int dx_core(void *args)
{
    GpuHostNicShmem *shm = (GpuHostNicShmem *)args;
    struct rte_gpu_comm_list *comm_list;
    struct pcap_packet_header burst_header;
    bool cap_packet;
    int ret = 0;

    printf("[D-Core %d] Starting...\n", shm->id);
    cudaSetDevice(GPU_ID);

    while (keep_alive(shm))
    {
        while (keep_alive(shm) && shm->dxlist_isreadable(&ret) == false)
            if (ret != 0)
            {
                fprintf(stderr, "[D-Core %d] rte_gpu_comm_get_status error: %s\n", shm->id, rte_strerror(ret));
                GpuHostNicShmem::force_quit = true;
                return EXIT_FAILURE;
            }

        if (killed(shm) && shm->dxlist_isreadable(&ret) == false)
            break;

        comm_list = shm->dxlist_read(&burst_header);

        for (uint32_t i = 0; i < comm_list->num_pkts; i++)
        {
            cap_packet = comm_list->pkt_list[i].size & 1;
            comm_list->pkt_list[i].size >>= 1;
            burst_header.caplen = cap_packet ? MAX_HLEN : comm_list->pkt_list[i].size;
            burst_header.len = comm_list->pkt_list[i].size;
            shm->stats.total_bytes += burst_header.len;
            shm->stats.stored_bytes += burst_header.caplen;

            GpuHostNicShmem::write.lock();
            fwrite_unlocked(&(burst_header), sizeof(pcap_packet_header), 1, shm->pcap_fp);
            fwrite_unlocked((const void *)comm_list->pkt_list[i].addr, burst_header.caplen, 1, shm->pcap_fp);
            GpuHostNicShmem::write.unlock();
        }

        shm->dxlist_clean();
    }
    return EXIT_SUCCESS;
}

int rx_core(void *args)
{
    GpuHostNicShmem *shm = (GpuHostNicShmem *)args;
    struct rte_mbuf *packets[1024];
    int i, ret;

    printf("[R-Core %d] Starting...\n", shm->id);
    cudaSetDevice(GPU_ID);

    while (keep_alive(shm))
    {
        i = 0;

        while (shm->rxlist_iswritable(&ret) == false)
        {
            printf("Yo, waiting!!!\n");
            if (ret != 0)
            {
                fprintf(stderr, "[R-Core %d] rte_gpu_comm_get_status error: %s\n", shm->id, rte_strerror(ret));
                GpuHostNicShmem::force_quit = true;
                return EXIT_FAILURE;
            }
        }

        /* Populate burst */
        while (keep_alive(shm) && i < (1024 - 8))
            i += rte_eth_rx_burst(NIC_PORT, shm->id, &(packets[i]), (1024 - i));

        if (i == 0)
            break;

        shm->stats.packets += i;

        if (shm->rxlist_write(packets, i) != 0)
        {
            fprintf(stderr, "[R-Core %d] rte_gpu_comm_populate_list_pkts error: %s\n", shm->id, rte_strerror(ret));
            GpuHostNicShmem::force_quit = true;
            return EXIT_FAILURE;
        }
        shm->rxlist_process(ceil(i, 32), 32);
        rte_pktmbuf_free_bulk(packets, i);
    }
    return EXIT_SUCCESS;
}